var fs = require('fs');
var test = require('tape');
var dstucert = require('..');

var obj = require('./Certificate.js');
var cer = fs.readFileSync(__dirname + '/Certificate.cer');

test('certificate decoding', function(t) {
  t.plan(1);
  var result = JSON.stringify(dstucert.decode(cer));
  var expected = JSON.stringify(obj);
  t.equal(result, expected);
});

test('certificate encoding', function(t) {
  t.plan(1);
  var result = JSON.stringify(dstucert.decode(dstucert.encode(obj)));
  var expected = JSON.stringify(obj);
  t.equal(result, expected);
});


test('certificate ping-pong encoding', function(t) {
  t.plan(1);
  var result = JSON.stringify(dstucert.decode(dstucert.encode(dstucert.decode(cer))));
  var expected = JSON.stringify(obj);
  t.equal(result, expected);
});
