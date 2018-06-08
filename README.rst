# Certipy

A simple python tool for creating certificate authorities and certificates on the fly.

## Usage

### Command line

Creating a certificate authority:

Certipy defaults to writing certs and store.json into a folder called `out` in your current directory.

```
$ certipy Foo
No store file at out/store.json. Creating a new one.
KeyCertPair(name='Foo', dir_name='/tmp/out/Foo', key_file='/tmp/out/Foo/Foo.key', cert_file='/tmp/out/Foo/Foo.crt', ca_file='/tmp/out/Foo/Foo.crt')
```

Creating and signing a key cert pair:
```
$ certipy Bar --ca-name Foo
KeyCertPair(name='Bar', dir_name='/tmp/out/Bar', key_file='/tmp/out/Bar/Bar.key', cert_file='/tmp/out/Bar/Bar.crt', ca_file='/tmp/out/Foo/Foo.crt')
```

### Code

Creating a certificate authority:

```
import certipy

certipy = Certipy(store_dir='/tmp')
certipy.create_ca('Foo')
cert_info = certipy.store_get('Foo') # KeyCertPair
```

Creating and signing a key cert pair:

```
import certipy

certipy = Certipy(store_dir='/tmp')
certipy.create_signed_pair('Bar', 'Foo')
cert_info = certipy.store_get('Bar') # KeyCertPair
```
