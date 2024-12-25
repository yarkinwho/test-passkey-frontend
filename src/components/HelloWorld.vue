<script setup lang="ts">

import { ref } from "vue"
import { SessionKit, Chains, PrivateKey, Session, TransactResult } from "@wharfkit/session";
import { WebRenderer } from "@wharfkit/web-renderer";
import { WebAuthnWallet } from "@/lib/wallet/passkey-wallet";
import { arrayToHex, hexToUint8Array, sortPubKeys } from "@/lib/utils";
import { decodeKey } from "@/lib/utils/passkey";
import { APIClient, PackedTransaction, SignedTransaction, Name, } from "@wharfkit/antelope"

import { Account, AccountKit } from "@wharfkit/account"
import { json } from "stream/consumers";
// import { PASSKEY_RP_ID } from "@/lib/const";


const sessionKit = ref()
const loginSession = ref()

const appPermission = ref('test')
const accountName = ref('actor1.xsat')

async function onClickGenAccount() {

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cid = "exsat-" + appPermission.value + "-" + accountName.value;

  const hashcid = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      Uint8Array.from(Array.from(cid).map(letter => letter.charCodeAt(0))).slice()
    )
  );

  console.log(location.hostname)

  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: {
        name: 'passkey-' + location.hostname,
        id: location.hostname
      },
      user: {
        id: hashcid,
        name: `${cid}`,
        displayName: `${cid}`,
      },
      pubKeyCredParams: [
        {
          type: "public-key",
          alg: -7,
        },
      ],
      timeout: 60000,
      challenge,
    },
  })) as PublicKeyCredential;

  if (!credential) return;

  console.log(credential)
  const id = arrayToHex(new Uint8Array(credential.rawId));

  const response = credential.response as AuthenticatorAttestationResponse;

  const attestationObject = arrayToHex(
    new Uint8Array(response.attestationObject)
  );

  const result = await decodeKey({
    rpid: location.hostname,
    id,
    attestationObject,
  });

  console.log("new passkey credential id:", result.credentialId);
  console.log("new passkey pubkey:", result.key);

  const options = {
    method: 'POST',
    headers: {
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 0,
      method: 'RegUser',
      params: [accountName.value, appPermission.value, result.key]
    })
  }

  const request = new Request("api", options)
  const r = await fetch(request)
  const data = await r.json();

  if (data.error) {
    return;
  }
  /*
    const packed = PackedTransaction.from(data.result)
    const rpc = new APIClient({ url: "https://chain2.exactsat.io" })
    const accountCreationResponse = await rpc.v1.chain.send_transaction2(packed, {
      return_failure_trace: false,
      retry_trx: true,
    })
  
    console.log(accountCreationResponse)
    */
}

async function onClickLogin() {
  const rpc = new APIClient({ url: "https://chain2.exactsat.io" })
  const info = await rpc.v1.chain.get_info()

  const kit = new SessionKit({
    appName: "passkey-wallet",
    chains: [{
      id: info.chain_id,
      url: "https://chain2.exactsat.io"
    }],
    ui: new WebRenderer(),
    walletPlugins: [new WebAuthnWallet(Name.from(accountName.value), Name.from(appPermission.value), null, null)],
  });

  sessionKit.value = kit
  const { session } = await kit.login();

  loginSession.value = session
}

async function onClickSign() {
  if (!loginSession.value)
    return;

  const options = {
    method: 'POST',
    headers: {
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 0,
      method: 'GenTx',
      params: [accountName.value, appPermission.value]
    })
  }

  const request = new Request("api", options)
  const r = await fetch(request)
  const data = await r.json();
  if (data.error) {
    return;
  }
  const packed = PackedTransaction.from(data.result)
  console.log(packed)

  // Append sig
  const tx = packed.getTransaction()

  console.log(JSON.stringify(tx))

  const packed2: PackedTransaction = await loginSession.value.transact(
    JSON.parse(JSON.stringify(tx)),
    {
      expireSeconds: 60,
      broadcast: false
    }
  ).then((result: TransactResult) => {
    if (result.resolved) {
      const signed = SignedTransaction.from({
        ...result.resolved.transaction,
        signatures: result.signatures,
      })
      return PackedTransaction.fromSigned(signed)
    }
    else {
      throw Error("Failed to prepare transaction")
    }
  }
  )
  console.log(packed2)
  packed2.signatures.push(packed.signatures[0])

  const rpc = new APIClient({ url: "https://chain2.exactsat.io" })
  const accountCreationResponse = await rpc.v1.chain.send_transaction2(packed2, {
    return_failure_trace: false,
    retry_trx: true,
  })

  console.log(accountCreationResponse)
}

</script>

<template>
  <div class="greetings">
    <h3>
      permission:
      <input v-model="appPermission">
      account name:
      <input v-model="accountName">
    </h3>
    <h3>

      <button @click="onClickGenAccount"> GenAccount</button>
      <button @click="onClickLogin"> login</button>
      <button @click="onClickSign"> sign</button>
    </h3>
  </div>
</template>

<style scoped>
h1 {
  font-weight: 500;
  font-size: 2.6rem;
  position: relative;
  top: -10px;
}

h3 {
  font-size: 1.2rem;
}

.greetings h1,
.greetings h3 {
  text-align: center;
}

@media (min-width: 1024px) {

  .greetings h1,
  .greetings h3 {
    text-align: left;
  }
}
</style>
