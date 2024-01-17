import json
import sys
from hashlib import sha256

import requests
from jose import jwk, jws
from pyld import jsonld

UNIVERSAL_RESOLVER_URL = 'https://dev.uniresolver.io/1.0/identifiers/'


def validate_vc(verifiable_credential):
    vc = json.loads(verifiable_credential)

    # Remove the proof attribute
    proof = vc.pop('proof')
    print('✍️ Using proof :')
    print(json.dumps(proof, sort_keys=True, indent=4))

    # Remove the verification method
    did = proof['verificationMethod'].split('#')[0]
    # Resolve verification method DID document
    print(f'\n🔎 Resolving DID {did}...')
    response = requests.get(UNIVERSAL_RESOLVER_URL + did)
    did_document = response.json()['didDocument']
    print(f'📜 Using DID document :')
    print(json.dumps(did_document, sort_keys=True, indent=4))

    # Extract JWK public key
    did_jwk = did_document['verificationMethod'][0]['publicKeyJwk']
    print(f'\n🔑 Using public key :')
    print(json.dumps(did_jwk, sort_keys=True, indent=4))
    public_key = jwk.construct(did_jwk)

    # Normalize/Canonize the VC with the URDNA2015 algorithm
    normalized_vc = jsonld.normalize(vc, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
    print('\n🔨 Normalized verifiable credential :')
    print(normalized_vc)

    # Encrypt the normalized/canonized VC with the SHA256 algorithm
    encrypted_vc = sha256(normalized_vc.encode()).hexdigest()
    print('\n🔐 Encrypted normalized verifiable credential :')
    print(encrypted_vc)

    # Build the JWT to verify by inserting the encrypted VC between the dots of the proof's JWS
    vc_jws = proof['jws'].split('.')
    vc_jwt = f'{vc_jws[0]}.{encrypted_vc}.{vc_jws[2]}'
    print('\n⭐️ Verifiable JWT :')
    print(vc_jwt)

    # Verify the VC's signature
    print('\n👮 Verifying the JWT...')
    try:
        jws.verify(vc_jwt, public_key, algorithms=['ES256'])
        print('\n🎉 The VC is valid')
    except:
        print('\n❌ The VC isn\'t valid')


if __name__ == '__main__':
    with open(sys.argv[1], "r") as vc_file:
        validate_vc(vc_file.read())
