# PushNotificationHelpers

A lightweight Delphi library for sending **Apple Push Notification Service (APNS)** and **Firebase Cloud Messaging (FCM)** notifications.

Version 2 has been completely rewritten and no longer depends on OpenSSL or JOSE. All cryptographic operations are implemented using **CryptoLib4Pascal**, making the library easier to deploy on both Windows and Linux.

## Features

* Pure Delphi implementation
* No OpenSSL required
* No JOSE dependency
* Supports Apple Push Notification Service (APNS)
* Supports Firebase Cloud Messaging (FCM)
* HTTP/2 support
* JWT authentication
* Windows and Linux compatible
* Backward compatible API with Version 1

## Dependencies

This project requires:

* CryptoLib4Pascal

https://github.com/Xor-el/CryptoLib4Pascal

## Why Version 2?

The original version used JOSE together with OpenSSL for JWT signing.

Although it worked well, deployment on Linux required installing and maintaining compatible OpenSSL libraries.

Version 2 removes that dependency completely.

Benefits:

* No external DLL or shared libraries
* No OpenSSL installation
* Easier deployment
* Same public API as Version 1
* Existing applications usually require only replacing the library units

## APNS Example

```delphi
program Example_APNS;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  APNS.Helper;

begin
  try
    var ResultStr := TAPNSHelper.SendPushNotification(
      'Device Token',
      'Your Bundle ID',
      'Your Key ID',
      'Your Team ID',
      'Path to .p8 private key',
      'Hello, World',
      'Title',
      1,
      'default',
      TServerType.stProduction
    );

    Writeln(ResultStr);

  except
    on E: Exception do
      Writeln(E.ClassName + ': ' + E.Message);
  end;
end.
```

## FCM Example

```delphi
program Example_FCM;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils, FCM.Helper;

begin
  try
    var Response := TFCMHelper.SendPushNotification(
      'Path to the Firebase service account JSON key file',
      'Device Token',
      'Your Project ID',
      'Title',
      'Hello, World'
    );

    Writeln(Response);

  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
```

## Migration from Version 1

No changes to your application code are normally required.

Simply replace the old library units with Version 2.

The public API has intentionally been kept compatible with Version 1.

## Tested with

* RAD Studio / Delphi
* Windows
* Linux

## License

MIT License

## Author

Thomas Rask

Contributions, suggestions and bug reports are welcome.
