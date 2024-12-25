import {
  AbstractWalletPlugin,
  WalletPluginSignResponse,
  Signature,
  Serializer,
  TransactContext,
  ResolvedSigningRequest,
  WalletPluginMetadata,
  LoginContext,
  WalletPluginLoginResponse,
  PermissionLevel,
} from "@wharfkit/session";
import { ec } from "elliptic";
import { SerialBuffer } from "../utils/serial-buffer";
import { hexToUint8Array, arrayToHex } from "../utils";
import {
  KeyType,
  signatureToString,
  stringToPublicKey,
} from "../utils/numeric";
import { AccountKit } from "@wharfkit/account"
import { Name, PublicKey } from "@wharfkit/antelope"

export class WebAuthnWallet extends AbstractWalletPlugin {
  public id = "wallet-plugin-passkey";
  public publicKey: PublicKey | null = null;

  readonly metadata: WalletPluginMetadata = WalletPluginMetadata.from({
    name: "Passkey Wallet",
    description: "Sign transactions using WebAuthn/Passkey",
  });

  constructor(public accountName: Name, public appPermission: Name, public passkeyId: string | null, publicKey: PublicKey | null = null) {
    super()
    if (publicKey)
      this.publicKey = publicKey
  }

  async login(context: LoginContext): Promise<WalletPluginLoginResponse> {

    if (!this.publicKey) {
      if (!context.chains[0])
        throw new Error("No chain defs found");
      const accountKit = new AccountKit(context.chains[0])
      const account = await accountKit.load(this.accountName)

      // Will throw if not found
      const p = account.permission(this.appPermission)

      if (p.required_auth.keys.length == 0)
        throw new Error("No public keys found");

      // There seems no cheap way to verify the keys, so we assume the first one is correct.
      this.publicKey = p.required_auth.keys[0].key
    }

    // Do not skip login even when passkeyId is passed in.
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credential = (await navigator.credentials.get({
      publicKey: {
        timeout: 60000,
        allowCredentials: this.passkeyId ? [
          {
            id: hexToUint8Array(this.passkeyId),
            type: "public-key",
          }
        ] : [],
        challenge: challenge,
      },
    })) as PublicKeyCredential;

    if (!credential) {
      throw new Error("No credential found");
    }

    this.passkeyId = arrayToHex(new Uint8Array(credential.rawId));

    console.log("passkey pubkey:", this.publicKey.toString());

    return {
      chain: context.chains[0].id,
      permissionLevel: PermissionLevel.from({
        actor: this.accountName,
        permission: this.appPermission,
      }),
    };
  }

  async sign(
    resolved: ResolvedSigningRequest,
    context: TransactContext
  ): Promise<WalletPluginSignResponse> {
    console.log("sign tx")
    if (!this.publicKey || !this.passkeyId)
      throw new Error("Haven't login yet!");

    const chainID = context.chain.id;
    const transaction = resolved.transaction;

    const serializedTransaction = Serializer.encode({
      object: transaction,
    }).array;

    const signBuf = new SerialBuffer();
    signBuf.pushArray(hexToUint8Array(chainID.hexString));
    signBuf.pushArray(serializedTransaction);

    // TODO: Add serializedContextFreeData
    signBuf.pushArray(new Uint8Array(32));

    const digest = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        signBuf.asUint8Array().slice().buffer
      )
    );

    const assertion = (await navigator.credentials.get({
      publicKey: {
        timeout: 60000,
        allowCredentials: [
          {
            id: hexToUint8Array(this.passkeyId),
            type: "public-key",
          },
        ],
        challenge: digest.buffer,
      },
    })) as PublicKeyCredential;

    if (!assertion) {
      throw new Error("No assertion found");
    }

    console.log("passkey pubkey:", this.publicKey.toString());

    // https://github.com/indutny/elliptic/pull/232
    const e = new ec("p256") as any;

    const publicKey = e
      .keyFromPublic(stringToPublicKey(this.publicKey.toString()).data.subarray(0, 33))
      .getPublic();

    const fixup = (x: Uint8Array) => {
      const a = Array.from(x);
      while (a.length < 32) a.unshift(0);
      while (a.length > 32)
        if (a.shift() !== 0)
          throw new Error("Signature has an r or s that is too big");
      return new Uint8Array(a);
    };

    const response = assertion.response as AuthenticatorAssertionResponse;

    const der = new SerialBuffer({
      array: new Uint8Array(response.signature),
    });
    if (der.get() !== 0x30) {
      throw new Error("Signature missing DER prefix");
    }
    if (der.get() !== der.array.length - 2) {
      throw new Error("Signature has bad length");
    }
    if (der.get() !== 0x02) {
      throw new Error("Signature has bad r marker");
    }
    const r = fixup(der.getUint8Array(der.get()));
    if (der.get() !== 0x02) {
      throw new Error("Signature has bad s marker");
    }
    const s = fixup(der.getUint8Array(der.get()));

    const whatItReallySigned = new SerialBuffer();
    whatItReallySigned.pushArray(new Uint8Array(response.authenticatorData));
    whatItReallySigned.pushArray(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", response.clientDataJSON)
      )
    );
    const hash = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        whatItReallySigned.asUint8Array().slice()
      )
    );
    const recid = e.getKeyRecoveryParam(
      hash,
      new Uint8Array(response.signature),
      publicKey
    );

    const sigData = new SerialBuffer();
    sigData.push(recid + 27 + 4);
    sigData.pushArray(r);
    sigData.pushArray(s);
    sigData.pushBytes(new Uint8Array(response.authenticatorData));
    sigData.pushBytes(new Uint8Array(response.clientDataJSON));

    const sig = signatureToString({
      type: KeyType.wa,
      data: sigData.asUint8Array().slice(),
    });

    return {
      signatures: [Signature.from(sig)],
    };
  }
}
