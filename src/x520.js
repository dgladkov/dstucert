var asn = require('asn1.js');

/*
  DirectoryString ::= CHOICE {
    printableString  PrintableString,
    utf8String       UTF8String,
    bmpString        BMPString
  }
 */
var DirectoryString = asn.define('DirectoryString', function() {
  this.choice({
    printableString: this.printstr(),
    utf8String: this.utf8str(),
    bmpString: this.bmpstr()
  });
});

var commonName = asn.define('X520commonName', function() {
  this.use(DirectoryString);
});

/*
  X520countryName ::= PrintableString (SIZE (2)) -- код згідно з міжнародним стандартом ISO 3166 (для України - UA)
 */

var countryName = asn.define('X520countryName', function() {
  this.printstr();
});

/*
  X520givenName ::= DirectoryString (SIZE (64))
 */
var givenName = asn.define('X520givenName', function() {
  this.use(DirectoryString);
});

/*
  X520localityName ::= DirectoryString (SIZE (64))
 */
var localityName = asn.define('X520localityName', function() {
  this.use(DirectoryString);
});

/*
  X520organizationalUnitName ::= DirectoryString (SIZE (64))
 */
var organizationalUnitName = asn.define('X520organizationalUnitName', function() {
  this.use(DirectoryString);
});

/*
  X520organizationName ::= DirectoryString (SIZE (64))
 */
var organizationName = asn.define('X520organizationName', function() {
  this.use(DirectoryString);
});

/*
  serialNumber ::= PrintableString (SIZE (64)) -- SPEC MISTAKE
  serialNumber ::= DirectoryString (SIZE (64)) -- REAL VALUE
 */
var serialNumber = asn.define('X520serialNumber', function() {
  this.use(DirectoryString);
});

/*
  X520stateOrProvinceName ::= DirectoryString (SIZE (64))
 */
var stateOrProvinceName = asn.define('X520stateOrProvinceName', function() {
  this.use(DirectoryString);
});

/*
  X520surname ::= DirectoryString (SIZE (64))
 */
var surname = asn.define('X520surname', function() {
  this.use(DirectoryString);
});

/*
  X520title ::= DirectoryString (SIZE (64))
 */
var title = asn.define('X520title', function() {
  this.use(DirectoryString);
});

module.exports = {
  commonName: commonName,
  countryName: countryName,
  givenName: givenName,
  localityName: localityName,
  organizationalUnitName: organizationalUnitName,
  organizationName: organizationName,
  serialNumber: serialNumber,
  stateOrProvinceName: stateOrProvinceName,
  surname: surname,
  title: title,
};
