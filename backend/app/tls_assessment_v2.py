"""Hardened, bounded TLS assessor for authorized scans."""
from __future__ import annotations
import hashlib
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from app.schemas import Evidence, PortService

TLS_PORTS={443,465,563,636,853,993,995,8443}
PROTOCOLS=(("TLSv1",ssl.TLSVersion.TLSv1),("TLSv1.1",ssl.TLSVersion.TLSv1_1),("TLSv1.2",ssl.TLSVersion.TLSv1_2),("TLSv1.3",ssl.TLSVersion.TLSv1_3))
TLS13_CIPHERS=("TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256","TLS_AES_128_CCM_SHA256","TLS_AES_128_CCM_8_SHA256")
WEAK=("RC4","3DES","DES-CBC","NULL","EXPORT","MD5","ANULL","ADH","CBC")
MAX_TLS12=128
TIMEOUT=4

def _grade(score:int)->str:
    return "A" if score>=90 else "B" if score>=80 else "C" if score>=65 else "D" if score>=50 else "F"

def _parse_certificate(der:bytes)->Dict[str,object]:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec,rsa
    cert=x509.load_der_x509_certificate(der)
    try: sans=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound: sans=[]
    key=cert.public_key()
    if isinstance(key,rsa.RSAPublicKey): kt,kb,curve="RSA",key.key_size,"Unknown"
    elif isinstance(key,ec.EllipticCurvePublicKey): kt,kb,curve="EC",key.key_size,key.curve.name
    else: kt,kb,curve=type(key).__name__,int(getattr(key,"key_size",0) or 0),"Unknown"
    now=datetime.now(timezone.utc)
    return {"subject":cert.subject.rfc4514_string(),"issuer":cert.issuer.rfc4514_string(),"san":list(sans),"not_before":cert.not_valid_before_utc.isoformat(),"not_after":cert.not_valid_after_utc.isoformat(),"days_remaining":round((cert.not_valid_after_utc-now).total_seconds()/86400,1),"serial":str(cert.serial_number),"signature_algorithm":cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown","key_type":kt,"key_bits":kb,"curve":curve,"sha256":hashlib.sha256(der).hexdigest(),"self_signed":cert.subject==cert.issuer,"der":der}

def _handshake(host:str,ip:str,port:int,version:Optional[ssl.TLSVersion]=None,cipher:Optional[str]=None,verify:bool=False):
    ctx=ssl.create_default_context(); ctx.check_hostname=verify; ctx.verify_mode=ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    if version is not None: ctx.minimum_version=version; ctx.maximum_version=version
    if cipher: ctx.set_ciphers(cipher)
    with socket.create_connection((ip,port),timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw,server_hostname=host) as s: return s.version(),s.cipher(),s.selected_alpn_protocol(),s.getpeercert(binary_form=True)

def _legacy(host,ip,port,version):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try: ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError: pass
    ctx.minimum_version=version; ctx.maximum_version=version
    with socket.create_connection((ip,port),timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw,server_hostname=host) as s:return s.version(),s.cipher()

def _probe_protocol(host,ip,port,label,version):
    try:
        v,c,_,_=_handshake(host,ip,port,version=version); return "supported",f"{label} accepted; negotiated {v} ({c[0] if c else 'Unknown'})"
    except ssl.SSLError as exc:
        if label in {"TLSv1","TLSv1.1"}:
            try:
                v,c=_legacy(host,ip,port,version); return "supported",f"{label} accepted; negotiated {v} ({c[0] if c else 'Unknown'})"
            except (ssl.SSLError,OSError,TimeoutError) as le:return "rejected",f"{label} rejected ({type(le).__name__})"
        return "rejected",f"{label} rejected ({type(exc).__name__})"
    except (OSError,TimeoutError):return "inconclusive",f"{label} probe timed out or connection failed"

def _openssl_ciphers()->List[str]:
    try:
        p=subprocess.run(["openssl","ciphers","-s","-tls1_2","ALL:@SECLEVEL=0"],capture_output=True,text=True,timeout=3,check=False)
        return list(dict.fromkeys(x.strip() for x in p.stdout.split(":") if x.strip())) if p.returncode==0 else []
    except (FileNotFoundError,subprocess.SubprocessError,OSError):return []

def _enumerate_tls12(host,ip,port):
    names=_openssl_ciphers() or [c["name"] for c in ssl.create_default_context().get_ciphers() if "TLS_AES" not in c["name"] and "CHACHA20" not in c["name"]]
    tested=min(len(names),MAX_TLS12); supported=[]; weak=[]
    for name in names[:MAX_TLS12]:
        try:
            _,c,_,_=_handshake(host,ip,port,version=ssl.TLSVersion.TLSv1_2,cipher=name)
            if c and c[0] not in supported:
                supported.append(c[0])
                if any(x in c[0].upper() for x in WEAK):weak.append(c[0])
        except (ssl.SSLError,OSError,TimeoutError):continue
    return supported,weak,tested,len(names)

def _enumerate_tls13(host,ip,port):
    supported=[]; weak=[]
    try: subprocess.run(["openssl","version"],capture_output=True,timeout=2,check=False)
    except (FileNotFoundError,subprocess.SubprocessError,OSError):return supported,weak,0,False
    for name in TLS13_CIPHERS:
        target=f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        try:
            p=subprocess.run(["openssl","s_client","-connect",target,"-servername",host,"-tls1_3","-ciphersuites",name,"-brief","-ign_eof"],input=b"",capture_output=True,timeout=TIMEOUT,check=False)
            text=(p.stdout+p.stderr).decode("utf-8",errors="ignore")
            if p.returncode==0 and ("Protocol version: TLSv1.3" in text or "Ciphersuite:" in text):supported.append(name)
        except (subprocess.SubprocessError,OSError):return supported,weak,len(supported),False
    return supported,weak,len(TLS13_CIPHERS),True

def _chain(host,ip,port):
    target=f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    try:
        p=subprocess.run(["openssl","s_client","-connect",target,"-servername",host,"-showcerts","-verify_return_error","-verify_hostname",host,"-brief","-ign_eof"],input=b"",capture_output=True,timeout=TIMEOUT,check=False)
        text=(p.stdout+p.stderr).decode("utf-8",errors="ignore")
        from cryptography import x509
        certs=[]
        for pem in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",text,re.S):
            c=x509.load_pem_x509_certificate(pem.encode()); certs.append({"subject":c.subject.rfc4514_string(),"issuer":c.issuer.rfc4514_string(),"not_after":c.not_valid_after_utc.isoformat(),"sha256":hashlib.sha256(c.public_bytes(__import__('cryptography').hazmat.primitives.serialization.Encoding.DER)).hexdigest()})
        m=re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)",text,re.I); trusted=bool(m and int(m.group(1))==0 and p.returncode==0)
        return {"available":True,"trusted":trusted,"verify_code":int(m.group(1)) if m else None,"verify_message":m.group(2) if m else "verification failed","chain_length":len(certs),"presented_certificates":certs,"hostname_verified":trusted}
    except (FileNotFoundError,subprocess.SubprocessError,OSError,ValueError):return {"available":False,"trusted":False,"verify_code":None,"verify_message":"OpenSSL chain validation unavailable","chain_length":0,"presented_certificates":[],"hostname_verified":False}

def assess_tls(host:str,ip:str,port:int)->Tuple[Dict[str,object],List[Evidence]]:
    ev=[]; r={"score":100,"grade":"A","supported_protocols":[],"rejected_protocols":[],"inconclusive_protocols":[],"supported_ciphers":[],"weak_ciphers":[],"certificate":{},"chain":{},"findings":[],"remediations":[],"cipher_enumeration_complete":False,"cipher_enumeration_coverage":{}}
    try:v,c,alpn,der=_handshake(host,ip,port)
    except (OSError,ssl.SSLError,TimeoutError) as exc:
        r.update(score=0,grade="F",findings=[{"id":"TLS_UNREACHABLE","severity":"INFO","detail":f"TLS handshake unavailable: {type(exc).__name__}"}]);return r,ev
    if v:ev.append(Evidence(type="tls_version",value=v,source="TLS handshake",confidence=.99))
    if c:ev.append(Evidence(type="tls_cipher",value=c[0],source="TLS handshake",confidence=.99))
    ev.append(Evidence(type="alpn",value=alpn or "Unknown",source="TLS handshake",confidence=.95))
    cert=_parse_certificate(der) if der else {};r["certificate"]={k:v for k,v in cert.items() if k!="der"}
    for k,t in (("sha256","certificate_sha256"),("subject","certificate_subject"),("issuer","certificate_issuer"),("not_before","certificate_not_before"),("not_after","certificate_not_after"),("days_remaining","certificate_days_remaining"),("key_type","certificate_key_type"),("key_bits","certificate_key_bits"),("curve","certificate_curve"),("signature_algorithm","certificate_signature_algorithm")):
        if k in cert:ev.append(Evidence(type=t,value=str(cert[k]),source="TLS certificate",confidence=1.0))
    if cert.get("san"):ev.append(Evidence(type="certificate_san",value=", ".join(cert["san"]),source="TLS certificate",confidence=1.0))
    f=[]
    for label,ver in PROTOCOLS:
        st,d=_probe_protocol(host,ip,port,label,ver)
        (r["supported_protocols"] if st=="supported" else r["rejected_protocols"] if st=="rejected" else r["inconclusive_protocols"]).append(label);ev.append(Evidence(type="tls_protocol_probe",value=d,source="bounded TLS version probe",confidence=.92 if st!="inconclusive" else .55))
        if st=="supported" and label in {"TLSv1","TLSv1.1"}:f.append({"id":"TLS_LEGACY_PROTOCOL","severity":"HIGH","detail":f"{label} is accepted by the service."})
    a,b,tested,total=_enumerate_tls12(host,ip,port); x,y,tested13,complete13=_enumerate_tls13(host,ip,port);r["supported_ciphers"]=sorted(set(a+x));r["weak_ciphers"]=sorted(set(b+y));r["cipher_enumeration_coverage"]={"tls12_tested":tested,"tls12_candidates":total,"tls13_tested":tested13,"tls13_candidates":len(TLS13_CIPHERS)};r["cipher_enumeration_complete"]=bool(complete13 and total<=MAX_TLS12)
    for n in r["supported_ciphers"]:ev.append(Evidence(type="tls_supported_cipher",value=n,source="bounded cipher probe",confidence=.94))
    for n in r["weak_ciphers"]:f.append({"id":"TLS_WEAK_CIPHER","severity":"HIGH","detail":f"Weak cipher accepted: {n}"})
    ch=_chain(host,ip,port);r["chain"]=ch;ev.append(Evidence(type="tls_chain_validation",value=f"trusted={ch['trusted']} code={ch['verify_code']}",source="OpenSSL trusted-chain validation",confidence=.98 if ch["available"] else .55))
    if ch["available"] and not ch["trusted"] and not cert.get("self_signed"):f.append({"id":"TLS_UNTRUSTED_CHAIN","severity":"HIGH","detail":f"Certificate chain is not trusted ({ch['verify_message']})."})
    days=cert.get("days_remaining")
    if isinstance(days,(int,float)):
        if days<0:f.append({"id":"TLS_CERT_EXPIRED","severity":"CRITICAL","detail":f"Certificate expired {abs(days):.1f} days ago."})
        elif days<=7:f.append({"id":"TLS_CERT_EXPIRING","severity":"HIGH","detail":f"Certificate expires in {days:.1f} days."})
        elif days<=30:f.append({"id":"TLS_CERT_EXPIRING","severity":"MEDIUM","detail":f"Certificate expires in {days:.1f} days."})
        elif days<=90:f.append({"id":"TLS_CERT_EXPIRING","severity":"LOW","detail":f"Certificate expires in {days:.1f} days."})
    sans=cert.get("san",[])
    if sans:
        try:matched=any(ssl.match_hostname({"subjectAltName":[("DNS",n)]},host) is None for n in sans)
        except (ssl.CertificateError,ValueError):matched=False
        if not matched:f.append({"id":"TLS_HOSTNAME_MISMATCH","severity":"HIGH","detail":f"Certificate SAN does not match {host}."})
    if cert.get("self_signed"):f.append({"id":"TLS_SELF_SIGNED","severity":"MEDIUM","detail":"Certificate is self-signed."})
    if cert.get("key_type")=="RSA" and int(cert.get("key_bits",0) or 0)<2048:f.append({"id":"TLS_WEAK_KEY","severity":"HIGH","detail":f"RSA key size is only {cert.get('key_bits')} bits."})
    if str(cert.get("signature_algorithm","")).lower() in {"sha1","md5"}:f.append({"id":"TLS_WEAK_SIGNATURE","severity":"HIGH","detail":f"Certificate uses {cert.get('signature_algorithm')} hashing."})
    if not any(p in r["supported_protocols"] for p in ("TLSv1.2","TLSv1.3")):f.append({"id":"TLS_NO_MODERN_PROTOCOL","severity":"HIGH","detail":"No modern TLS protocol was positively negotiated."})
    penalty={"CRITICAL":30,"HIGH":20,"MEDIUM":10,"LOW":3,"INFO":0};r["score"]=max(0,100-sum(penalty.get(z["severity"],0) for z in f));r["grade"]=_grade(r["score"]);r["findings"]=f
    rem={"TLS_LEGACY_PROTOCOL":"Disable TLS 1.0/1.1 and require TLS 1.2 or TLS 1.3.","TLS_WEAK_CIPHER":"Disable legacy/weak cipher suites and prefer AEAD suites with forward secrecy.","TLS_CERT_EXPIRED":"Renew the certificate and deploy a valid chain.","TLS_CERT_EXPIRING":"Renew the certificate before expiry.","TLS_HOSTNAME_MISMATCH":"Install a certificate whose SAN contains the scanned hostname.","TLS_UNTRUSTED_CHAIN":"Install the complete certificate chain from a trusted CA.","TLS_SELF_SIGNED":"Use a trusted CA certificate for public services.","TLS_WEAK_KEY":"Use RSA >= 2048 bits or a modern EC public key.","TLS_WEAK_SIGNATURE":"Replace SHA-1/MD5-signed certificates.","TLS_NO_MODERN_PROTOCOL":"Enable TLS 1.2 and/or TLS 1.3."};r["remediations"]=[{"id":z["id"],"action":rem[z["id"]]} for z in f if z["id"] in rem]
    for z in r["remediations"]:ev.append(Evidence(type="tls_remediation",value=z["action"],source="AetherMap TLS assessor",confidence=.90))
    return r,ev

async def assess_services_tls(services:List[PortService])->List[PortService]:
    import asyncio
    sem=asyncio.Semaphore(8)
    async def one(s:PortService):
        if s.protocol.lower()!="tcp" or s.port not in TLS_PORTS or s.ip=="Unknown":return s
        async with sem:r,e=await asyncio.to_thread(assess_tls,s.host,s.ip,s.port)
        s.tls_score=int(r["score"]);s.tls_grade=str(r["grade"]);s.tls_supported_protocols=list(r["supported_protocols"]);s.tls_supported_ciphers=list(r["supported_ciphers"]);s.tls_weak_ciphers=list(r["weak_ciphers"]);s.tls_certificate=dict(r["certificate"]);s.tls_findings=list(r["findings"]);s.tls_remediations=list(r["remediations"]);s.tls_cipher_enumeration_complete=bool(r["cipher_enumeration_complete"]);s.tls_cipher_enumeration_coverage=dict(r["cipher_enumeration_coverage"]);s.tls_chain=dict(r["chain"]);s.evidence.extend(e);return s
    return await asyncio.gather(*(one(s) for s in services))
