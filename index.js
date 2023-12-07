const { Command } = require('commander');
const crypto = require("crypto");
const elliptic = require("elliptic");
const didJWT = require("did-jwt");
const didJWTVC = require("did-jwt-vc");
const { Resolver } = require('did-resolver');
const { getResolver } = require('web-did-resolver');
const fs = require('fs');

const program = new Command();

program
  .name('vc')
  .description('VC command line tool')
  .version('1.0.0');

program.command('rsa-gen') 
   .description('generate rsa public/private key')
   .argument('<outdir>','output directory')
   .option('-n, --name <name>','name of key pair', 'rsa')
   .option('-w, --webid <name>', 'webid', undefined)
   .option('-f, --format <format>', 'json|ttl', 'ttl')
   .action(async(outdir,options) => {
      await createRSA(outdir,options)
   });

program.command('rsa-sign')
   .description('sign a text input with a private key')
   .argument('<file>','data to be signed')
   .option('--priv <rsa.priv>','private key')
   .action(async(file,options) => {
      const data = fs.readFileSync(file,{ encoding: 'utf8'} );
      const key  = fs.readFileSync(options.priv,{ encoding: 'utf8'} );
      const signature = await createRSASignature(data,key);
      process.stdout.write(signature.toString('base64'));
   });

program.command('rsa-verify')
   .description('verify a signature for a text input')
   .argument('<file>','data to be verified')
   .argument('<signature>','signature')
   .option('--pub <rsa.pub>','public key')
   .action(async(file,signature,options) => {
      const data = fs.readFileSync(file,{ encoding: 'utf8'} );
      const b64  = fs.readFileSync(signature,{ encoding: 'utf8' } );
      const key  = fs.readFileSync(options.pub,{ encoding: 'utf8'} );
      const sig  = Buffer.from(b64, 'base64')
      const res = await verifyRSA(data,sig,key);
      if (res) {
         console.log("verified: true");
         process.exit(0);
      }
      else {
         console.log("verified: false");
         process.exit(2);
      }
   });

program.command('did')
  .description('create a did')
  .argument('<domain>', 'web domain name')
  .option('-o, --outdir <directory>', 'output directory', 'output')
  .action(async(domain, options) => {
      await createDid(domain,options.outdir);
  });

program.command('jwt')
  .description('create a jwt')
  .argument('<priv.key>', 'path to private key')
  .argument('<did>','did identifier')
  .option('-n, --name <name>','name',undefined)
  .action(async(privKeyPath,did,options) => {
      const key = fs.readFileSync(privateKeyPath, { encoding: 'utf8'});
      // We need write to prevent adding an extra new line
      process.stdout.write(await createDidJWT(key,did,options.name));
  });

program.command('jwt-verify')
  .description('verify a jwt')
  .argument('<jwt>', 'path to a jwt')
  .argument('<did>','did identifier')
  .action(async(jwtPath,did) => {
      const res = await verifyDidJWT(fs.readFileSync(jwtPath,{ encoding: 'utf8' }),did);

      if (res && res['verified']) {
         console.log(`verified: true`);
         console.log(`issuer: ${res['issuer']}`);
      }
      else {
         console.log(`verified: false`);
         process.exit(2);
      }
  });

program.command('vc')
  .description('create a vc')
  .argument('<priv.key>','path to the private key')
  .argument('<did>','did identifier')
  .argument('<payload>','vc payload')
  .action(async(privKeyPath,did,payloadPath) => {
      const key = fs.readFileSync(privKeyPath,{ encoding: 'utf8' });
      const payload = JSON.parse( fs.readFileSync(payloadPath,{ encoding: 'utf8' }));
      // We need write to prevent adding an extra new line
      process.stdout.write(await createVC(key,did,payload));
  });

program.command('vc-verify') 
  .description('verify a vc')
  .argument('<jwt.vc>','path to vc in jwt form')
  .action(async(jwtPath) => {
      const vcJwt = fs.readFileSync(jwtPath,{ encoding: 'utf8' });
      const res = await verifyVCJWT(vcJwt);

      if (res && res['verified']) {
         console.log(`verified: true`);
         console.log(`issuer: ${res['issuer']}`);
      }
      else {
         console.log(`verified: false`);
         process.exit(2);
      }
  });

program.command('vc-presentation')
  .description('create a vc presentation')
  .argument('<priv.key>','path to private key')
  .argument('<did>','did identifier')
  .argument('<jwt.vc>','path to vc in jwt form')
  .argument('<template>','path to presentation template')
  .action(async(privKeyPath,did,jwtPath,templatePath) => {
      const key = fs.readFileSync(privKeyPath,{ encoding: 'utf8' });
      const vcJwt = fs.readFileSync(jwtPath,{ encoding: 'utf8' });
      const template = JSON.parse( fs.readFileSync(templatePath,{ encoding: 'utf8' }));
      // We need write to prevent adding an extra new line
      process.stdout.write(await createVCPresentation(key,did,vcJwt,template));
  });

program.command('vc-presentation-verify') 
  .description('verify a vc')
  .argument('<jwt.pres>','path to vc presentation in jwt form')
  .action(async(jwtPath) => {
      const vcJwt = fs.readFileSync(jwtPath,{ encoding: 'utf8' });
      const res = await verifyVCPresentationJWT(vcJwt);

      if (res && res['verified']) {
         console.log(`verified: true`);
         console.log(`issuer: ${res['issuer']}`);
      }
      else {
         console.log(`verified: false`);
         process.exit(2);
      }
  });

program.parse();

async function createRSA(outdir,options) {
   if (! fs.existsSync(outdir)) {
      console.log(`generating output directory ${outdir}`);
      fs.mkdirSync(outdir);
   }
   const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      // The standard secure default length for RSA keys is 2048 bits
      modulusLength: 2048
   });
   const pubKey = publicKey.export({type: 'spki', format: 'pem'}).toString()
   const privKey = privateKey.export({type: 'pkcs8', format: 'pem'}).toString()
   fs.writeFileSync(`${outdir}/${options.name}.pub.pem`,pubKey,{ encoding: 'utf8' });
   fs.writeFileSync(`${outdir}/${options.name}.priv.pem`,privKey,{ encoding: 'utf8' });
   if (options.webid) {
      if (options.format === 'json') {
         console.log(JSON.stringify({
            "publicKey": {
               "id": "https://my-example.com/actor#main-key",
               "owner": "https://my-example.com/actor",
               "publicKeyPem": pubKey
            }
         },null,4));
      }
      else {
         const truncWebid = options.webid.replace(/\#.*$/g,'');
         console.log(`    <https://w3id.org/security#publicKey> <${truncWebid}#main-key> .`);
         console.log(`<${truncWebid}#main-key> <https://w3id.org/security#owner> <${options.webid}> .`);
         console.log(`<${truncWebid}#main-key> <https://w3id.org/security#publicKeyPem> '''${pubKey}''' .`);
      }
   }
}

async function createRSASignature(data,key) {
   const algorithm = "SHA256";
   let signature = crypto.sign(algorithm, Buffer.from(data), key);
   return signature;
}

async function verifyRSA(data,signature,key) {
   const algorithm = "SHA256";
   return crypto.verify(algorithm, Buffer.from(data), key, signature);
}

async function createDid(domain,outdir) {
   if (! fs.existsSync(outdir)) {
       console.log(`generating output directory ${outdir}`);
       fs.mkdirSync(outdir);
   }

   console.log(`generating new private key`);
   const size = 32;
   const randomString = crypto.randomBytes(size).toString("hex");
   const key = randomString;

   console.log(`writing key to ${outdir}/private.txt`);
   fs.writeFileSync(`${outdir}/private.txt`,key, 'utf8');

   console.log(`writing did document to ${outdir}/did.json`);

   const ec = new elliptic.ec('secp256k1');
   const prv = ec.keyFromPrivate(key, 'hex');
   const pub = prv.getPublic();

   fs.writeFileSync(`${outdir}/did.json`, JSON.stringify({
       "@context": [
           "https://www.w3.org/ns/did/v1",
           "https://w3id.org/security/suites/jws-2020/v1"
       ],
       "id" : `did:web:${domain}`,
       "verificationMethod": [{
           "id": `did:web:${domain}#owner`,
           "type": "JsonWebKey2020",
           "controller": `did:web:${domain}`,
           "publicKeyJwk": {
               "kty": "EC",
               "crv": "secp256k1" ,
               "x": pub.x.toBuffer().toString('base64') ,
               "y": pub.y.toBuffer().toString('base64')
           }        
       }],
       "authentication": [
           `did:web:${domain}#owner`
       ],
       "assertionMethod": [
           `did:web:${domain}#owner`
       ]
   },null,4));

   console.log(`Publish ${outdir}/did.json on https://${domain}/.well-known/did.json`);
   console.log(`Keep ${outdir}/private.txt at a secure place`);
   console.log(`Test your did:web:${domain} at https://resolver.identity.foundation`);
}

async function createDidJWT(key, did, name) {
   const signer = didJWT.ES256KSigner(didJWT.hexToBytes(key));

   let jwt = await didJWT.createJWT(
      { aud: did, name: name },
      { issuer: did, signer },
      { alg: 'ES256K' }
   )

   return jwt;
}

async function verifyDidJWT(jwt,did) {
   try {
      const webResolver = getResolver();
      const resolver = new Resolver({
         ...webResolver
      });

      let verificationResponse = await didJWT.verifyJWT(jwt, {
         resolver,
         audience: did
      });

      return verificationResponse;
   }
   catch (e) {
      return undefined;
   }
}

async function createVC(key,did,payload) {
   const signer = didJWT.ES256KSigner(didJWT.hexToBytes(key))

   const issuer = {
      did: did,
      signer: signer
   }

   const vcPayload = {
      sub: did,
      nbf: timestamp(),
      vc: payload
   }

   return await didJWTVC.createVerifiableCredentialJwt(vcPayload, issuer);
}

async function verifyVCJWT(vcJwt) {
   try {
      const resolver = new Resolver(getResolver());
      const verifiedVC = await didJWTVC.verifyCredential(vcJwt, resolver);
      
      return verifiedVC;
   }
   catch (e) {
      return undefined;
   }
}

async function createVCPresentation(key,did,vcJwt,template) {
   const signer = didJWT.ES256KSigner(didJWT.hexToBytes(key))

   // Prepare an issuer
   const issuer = {
      did: did,
      signer: signer
   }

   template['verifiableCredential'] = [vcJwt];

   const vpPayload = {
      vp: template
   }

   return await didJWTVC.createVerifiablePresentationJwt(vpPayload, issuer)
}

async function verifyVCPresentationJWT(vcJwt) {
   try {
      const resolver = new Resolver(getResolver());
      const verifiedVC = await didJWTVC.verifyPresentation(vcJwt, resolver);
     
      return verifiedVC;
   }
   catch (e) {
      return undefined;
   }
}

function timestamp() {
   return Math.floor( Date.now() / 1000);
}