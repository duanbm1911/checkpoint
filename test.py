import qrcode
import pyotp

for i in ['dungnt63', 'dongtv6']:
    key = pyotp.random_base32()
    print(i, key)
    totp = pyotp.TOTP(key)
    uri = totp.provisioning_uri(name=i, issuer_name='ICMS Authenticate')
    qrcode.make(uri).save(f'{i}.png')
    