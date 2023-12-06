# VCTOOLS

Based on https://github.com/skounis/vc-hello-didweb

A collection of command line tools to create and validate Verifiable Credentials.

## INSTALL

```
npm install
```

## USAGE

### Create a DID document.

Create a new decentralized identifier using the `web` method:

```
node index.js patrickhochstenbach.net outdir
```

In the `outdir` you'll find two files:

- `private.txt` : keep this one safe this is your private key
- `did.json` : publish this document on your website on a `well-known` path.
   - Mine is at https://patrickhochstenbach.net/.well-known/did.json

### Create a signed version of the DID

To prove you are really the owner of the DID, you can create a signed document that contains the DID together with a signature:

```
node index.js jwt --name "Patrick" jwt outdir/private.txt did:web:patrickhochstenbach.net > outdir/test.jwt
```

The output `outdir/test.jwt` can now be sent to a verifier to validate.

### Validate the JWT output of the previous step

```
node index.js jwt-verify outdir/test.jwt did:web:patrickhochstenbach.net
```

### Create a Verifiable Credential

Create a Verifiable Credential with the `example/bachelor_degree.json` payload.

The idea is here that e.g. holder creates payload that is signed by an issuer.
The issuer uses her DID and private key for that. In this example we assume that
the holder and issuer are the same entity.

```
node index.js vc outdir/private.txt did:web:patrickhochstenbach.net examples/bachelor_degree.json > outdir/test.vc
```

### Validate the JWT output of the previous step

The holder of the JWT of the previous step can check if it is valid:

```
node index.js vc-verify outdir/test.vc
```

### Create a Verifiable Credential Presentation

Based on a Verifiable Credential in posession a Presentation can be created that
can be shared with a third party. The presentation can add other metadata fields
to the VC.

```
node index.js vc-presentation outdir/private.txy did:web:patrickhochstenbach.net outdir/test.vc examples/my_presentation.json > outdir/test.vc.pres
```

### Validate the Verifiable Credential Presentation

An verifier can validate the received Presentation

```
node index.js vc-presentation-verify outdir/test.vc.pres
```
