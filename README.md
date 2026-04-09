You can now install a laravel encrypter / decrypter with `go install github.com/omniboost/laravel-encrypt@latest`

Usage is:
```
Usage:
laravel_encrypt [flags]

Flags:
-k, --app_key string   APP_KEY used for encryption, can be prefixed with 'base64:' which will automatically decode it before using the key
-d, --decrypt          If set input will be decrypted
-h, --help             help for laravel_encrypt
-r, --raw              Don't strip newlines on single line inputAPP_KEY can also be an environment variable :wink:
```

if used with piped output, it also omit the newline in the output.

sample encryption:

```echo "test" | laravel-encrypt | pbcopy```

sample decryption

```pbpaste | laravel-encrypt -d```

(ofcourse the pbpaste, just gets data from your clipboard, so if you run the 2 commands in a row, it will output test)
