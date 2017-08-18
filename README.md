# dstucert

Certificate encoder/decoder based on http://zakon2.rada.gov.ua/laws/show/z1398-12#n25 specification.

Based on https://github.com/dstucrypt/jkurwa/blob/master/lib/spec/rfc3280.js

## Usage

```js
var fs = require(fs);
var dstucert = require('dstcert');

var cert = fs.readFileSync('certificate.cer');
var obj = dstucert.decode(cert);
var cert2 = dstucert.encode(cert);
```

## License

MIT
