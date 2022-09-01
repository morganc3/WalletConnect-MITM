# Description
This is an extension for [mitmproxy](https://mitmproxy.org/) that decrypts [WalletConnect](https://walletconnect.com/) 
websocket messages in a content view. Additionally, it contains an mitmproxy command to encrypt, HMAC, and send new messages 
to an existing websocket channel. It can also be used without mitmproxy to decrypt and re-encrypt messages.

# Usage

## Viewing WalletConnect messages decrypted: 
1. `mitmproxy -s ./wallet_connect_decryptor.py`
2. Select the WalletConnect websocket traffic (look for HTTP 101 response) and press enter
3. Select the "WebSocket Messages" tab
4. You should now see encrypted WalletConnect messages.
5. Type the following command using the "key" parameter from the WalletConnect URL: `:wc_set_key ${KEY}`
6. Press "m" and select the "wallet_connect_decryptor" mode
7. The WebSocket messages will now be decrypted in your view

## Sending a WalletConnect message:
1. Establish a WalletConnect session and set your key (as shown in step 5 above)
2. Enter the command `:wc_send ${PAYLOAD_FILE} true` where `PAYLOAD_FILE` is a path to a file with a payload to be encrypted and HMAC'd
3. The boolean argument indicates if the message is for the client or the server

See `./example_payload_to_wc_send.json` for an example of a message that can be sent with the `wc_send` mitmproxy command.
The first parameter in the example is a hex encoded "hello world" message, anda the second parameter is your wallet address.

walletconnect.org hosts an example dApp that can be connected with WalletConnect at https://example.walletconnect.org/ 

## Decrypting a message without using mitmproxy
```
    wce = WalletConnectEncryption(key, msg)

    # decrypt payload of original message
    plaintext_payload = wce.decrypt_from_ws_message(msg)
    print("Plaintext payload:")
    print(plaintext_payload)
    print("\n")
```

# Quickstart on MacOS with Docker

If you are on Mac and have Docker installed, mitmproxy with the extension can be easily setup in a
container by running `./macos-docker-setup.sh`.

This will start mitmproxy with the WalletConnect extension in a container, with the current directory mounted and
with port 8080 forwarded from the host.

Once the bash script completes, mitmproxy should be running and you should have a `./mitmproxy-ca-cert.pem`
file in the current directory. You must trust this certificate on your host in order to proxy
TLS traffic. In FireFox, go to Settings -> Privacy & Security -> Certificates -> View Certificates -> import. Select the `./mitmproxy-ca-cert.pem` file, and check "Trust this certificate to identify websites".

Now, simply proxy traffic from your browser to 127.0.0.1:8080. This can be setup in FireFox at Settings -> Network Settings -> Settings -> Manual proxy configuration
