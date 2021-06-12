# pwnedpass

A simple package to check if the password was exposed in data breaches. It uses the [Have I Been Pwned API](https://haveibeenpwned.com).

### Usage

That package is intended to use on client-side, it's compatible with WebAssembly too. You can simple use:

    if leaked, _ := pwnedpass.IsCompromised([]byte("weakpassword")); leaked {
        // Password was leaked in some data breach.
    }

### Cache

Currently, there's no cache: that package was initially intended to be used on client-side. If you want to used it on server-side (the server performs the verification) you can to download the [Pwned Passwords list](https://haveibeenpwned.com/Passwords) and use it instead of calling HIBP API.

### Permissions

- Android: It will require `android.permission.INTERNET` permission.
- WebAssembly: It may require `connect-src api.pwnedpasswords.com` (or equivalent) if using CSP.

### Privacy

That package can be used to check the "password-strength" upon user sign-up. This package will transfer a partial hash of the user's passwords, over the internet to a third-party service. You may need to inform the user about the usage of the [HIBP API](https://haveibeenpwned.com/Privacy). 