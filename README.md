# Certipy

A simple python tool for creating certificate authorities and certificates on the fly.

## Usage

### Command line

Creating a certificate authority:

Certipy defaults to writing certs and store.json into a folder called `out` in your current directory.

```
$ certipy foo
No store file at out/store.json. Creating a new one.
KeyCertPair(name='foo', dir_name='/tmp/out/foo', key_file='/tmp/out/foo/foo.key', cert_file='/tmp/out/foo/foo.crt', ca_file='/tmp/out/foo/foo.crt')
```

Creating and signing a key cert pair:
```
$ certipy bar --ca-name foo
KeyCertPair(name='bar', dir_name='/tmp/out/bar', key_file='/tmp/out/bar/bar.key', cert_file='/tmp/out/bar/bar.crt', ca_file='/tmp/out/foo/foo.crt')
```

### Code

Creating a certificate authority:

```
import certipy

certipy = Certipy(store_dir='/tmp')
certipy.create_ca('foo')
cert_info = certipy.store_get('foo') # KeyCertPair
```

Creating and signing a key cert pair:

```
import certipy

certipy = Certipy(store_dir='/tmp')
certipy.create_signed_pair('bar', 'foo')
cert_info = certipy.get('bar') # KeyCertPair
```
