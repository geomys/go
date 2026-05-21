# Geomys FIPS 140-3 Wasm Go module

> [!WARNING]
> This branch is prepared for a Geomys customer and is not intended for
> public use. Until and unless support is integrated in the upstream repository
> and in a public FIPS 140-3 Security Policy, these instructions should only be
> relied upon to the extent you are advised privately by Geomys.

This branch provides the Go 1.26.3 toolchain, with additional support for
building WebAssembly modules that can run in FIPS 140-3 mode with the new
FIPS 140-3 Go Cryptographic Module v1.0.1.

The instructions below show how to compile a simple Go program as a Wasm module
in FIPS 140-3 mode. Aside from the custom toolchain and GOFIPS140=v1.0.1
environment variable, the process and capabilities are the same as building and
running any other Go Wasm module.

```
# Clone this branch.
GOROOT=$PWD/go-wasm-fips140
git clone https://github.com/geomys/go $GOROOT --branch=fips140-wasm --depth=1

# Compile the Go toolchain.
(cd $GOROOT/src; ./make.bash)

# Create an example Go program.
cat > main.go <<'EOF'
package main
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/sha256"
	"fmt"
)
func main() {
	fmt.Printf("FIPS 140-3 mode enabled: %t\n", fips140.Enabled())
	fmt.Printf("FIPS 140-3 module version: %s\n", fips140.Version())
	key, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		fmt.Printf("Error generating ECDSA key: %v\n", err)
		return
	}
	message := sha256.Sum256([]byte("Hello, FIPS 140-3!"))
	sig, err := key.Sign(nil, message[:], crypto.SHA256)
	if err != nil {
		fmt.Printf("Error signing message: %v\n", err)
		return
	}
	fmt.Printf("Signature generated successfully: %x\n", sig)
}
EOF

# Build the Wasm module.
GOFIPS140=v1.0.1 GOOS=js GOARCH=wasm $GOROOT/bin/go build -o main.wasm main.go

# Copy module instantiation JavaScript.
cp $GOROOT/lib/wasm/wasm_exec.js .

# Create an HTML page to load the Wasm module.
cat > index.html <<'EOF'
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<script src="wasm_exec.js"></script>
<script type="module">
const go = new Go();
const source = await (await fetch("main.wasm")).arrayBuffer();
const result = await WebAssembly.instantiate(source, go.importObject);
await go.run(result.instance, result.module, source);
</script>
EOF

# Run a local web server and check the console for output.
npx http-server -o -g
```
