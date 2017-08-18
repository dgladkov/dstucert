var fs = require('fs');
var test = require('tape');
var dstucert = require('..');

var cer = fs.readFileSync(__dirname + '/Certificate.cer');
var obj = JSON.parse(fs.readFileSync(__dirname + '/Certificate.json'));
var buf = new Buffer(10);
buf.fill(0);

test('certificate decoding', function (t) {
  t.plan(1);
  var result = JSON.stringify(dstucert.decode(cer));
  var expected = JSON.stringify(obj);
  t.equal(result, expected);
});

test('certificate ping-pong encoding', function (t) {
  t.plan(1);
  var result = JSON.stringify(dstucert.decode(dstucert.encode(dstucert.decode(cer))));
  var expected = JSON.stringify(obj);
  t.equal(result, expected);
});
