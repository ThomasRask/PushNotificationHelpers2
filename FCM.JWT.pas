unit FCM.JWT;

{
  FCM JWT generator using CryptoLib4Pascal
  Algorithm: RS256 (RSA PKCS#1 v1.5 + SHA-256)
  Input: Firebase service account JSON (contains RSA private key)
  Output: Compact JWT token
}

interface

uses
  System.SysUtils, System.Classes, System.IOUtils,
  ClpPrivateKeyInfoFactory, ClpIECParameters, ClpIRsaParameters,
  System.JSON, JWT.CryptoLib.Utils;

type
  TFCM_JWT = class
  private
    /// <summary>
    /// Sign data using RSA PKCS#1 v1.5 + SHA-256
    /// </summary>
    class function SignRS256(const AData: TBytes;
      const APemKey: string; var AError: string): TBytes;

  public
    /// <summary>
    /// Generates a JWT for FCM/Google OAuth2
    /// </summary>
    /// <param name="AServiceAccountJSONPath">Firebase service account JSON path</param>
    /// <param name="AError">Output error message</param>
    /// <returns>JWT token or empty string on error</returns>
    class function Generate(const AServiceAccountJSONPath: string;
      var AError: string): string;
  end;

implementation

uses
  // CryptoLib4Pascal units
  ClpCryptoLibTypes,
  ClpIAsymmetricKeyParameter,
  ClpPrivateKeyFactory,
  ClpISigner,
  ClpSignerUtilities;

{ TFCM_JWT }

class function TFCM_JWT.SignRS256(const AData: TBytes;
  const APemKey: string; var AError: string): TBytes;
var
  KeyBytes: TBytes;
  PrivKey: IAsymmetricKeyParameter;
  Signer: ISigner;
begin
  Result := nil;
  try
    // 1. Read DER bytes from PEM
    KeyBytes := TJWTCryptoUtils.LoadPemBytes(APemKey);
    if Length(KeyBytes) = 0 then
    begin
      AError := 'RS256: Unable to load key from PEM';
      Exit;
    end;

    // 2. Parsing PKCS#8 private key
    //    Firebase service account JSON contains RSA key in PKCS#8 format
    PrivKey := TPrivateKeyFactory.CreateKey(KeyBytes);
    if not Supports(PrivKey, IRsaPrivateCrtKeyParameters) then
    begin
      AError := 'RS256: The key is not an RSA private key.';
      Exit;
    end;

    // 3. SHA256withRSA = RSA PKCS#1 v1.5 s SHA-256 digestem
    Signer := TSignerUtilities.GetSigner('SHA-256withRSA');

    // 4. Initializing for signing
    Signer.Init(True, PrivKey);

    // 5. Forwarding data
    Signer.BlockUpdate(AData, 0, Length(AData));

    // 6. RSA signature is already in the correct format (not DER-wrapped like ECDSA)
    Result := Signer.GenerateSignature;

  except
    on E: Exception do
    begin
      AError := 'RS256 signing error: ' + E.Message;
      Result := nil;
    end;
  end;
end;

class function TFCM_JWT.Generate(const AServiceAccountJSONPath: string;
  var AError: string): string;
var
  JSONContent: string;
  JSONObj: TJSONObject;
  PrivateKey, ClientEmail: string;
  Header, Payload: string;
  SigningInput, Signature: TBytes;
  IssuedAt, Expiration: Int64;
begin
  Result := '';

  if not TFile.Exists(AServiceAccountJSONPath) then
  begin
    AError := 'FCM JWT: Service account JSON not found: ' + AServiceAccountJSONPath;
    Exit;
  end;

  try
    // We load and parse the service account JSON
    JSONContent := TFile.ReadAllText(AServiceAccountJSONPath, TEncoding.UTF8);
    JSONObj := TJSONObject.ParseJSONValue(JSONContent) as TJSONObject;
    if not Assigned(JSONObj) then
    begin
      AError := 'FCM JWT: Unable to parse service account JSON';
      Exit;
    end;

    try
      // We extract the necessary values
      PrivateKey := JSONObj.GetValue<string>('private_key');
      ClientEmail := JSONObj.GetValue<string>('client_email');

      if PrivateKey.IsEmpty then
      begin
        AError := 'FCM JWT: private_key missing in JSON';
        Exit;
      end;

      if ClientEmail.IsEmpty then
      begin
        AError := 'FCM JWT: client_email missing in JSON';
        Exit;
      end;

      // Timestamps
      IssuedAt := TJWTCryptoUtils.UnixNow;
      Expiration := TJWTCryptoUtils.UnixNowPlusSeconds(3600); // 1 hour

      // JWT Header (RS256)
      Header := '{"alg":"RS256","typ":"JWT"}';

      // JWT Payload for Google OAuth2
      // iss: service account email
      // sub: service account email (for impersonation, same as iss)
      // aud: Google token endpoint
      // scope: FCM authorization
      // iat/exp: token validity
      Payload := Format(
        '{"iss":"%s",' +
        '"sub":"%s",' +
        '"aud":"https://oauth2.googleapis.com/token",' +
        '"scope":"https://www.googleapis.com/auth/firebase.messaging",' +
        '"iat":%d,' +
        '"exp":%d}',
        [ClientEmail, ClientEmail, IssuedAt, Expiration]
      );

      // Compile the signing input
      SigningInput := TJWTCryptoUtils.BuildSigningInput(Header, Payload);

      // Signing RS256
      // Firebase JSON private_key contain PEM s \n like escape sequence
      // need to convert them to real newlines
      PrivateKey := PrivateKey.Replace('\n', #10, [rfReplaceAll]);

      Signature := SignRS256(SigningInput, PrivateKey, AError);
      if Signature = nil then
        Exit; // AError is already set

      // Build the final JWT
      Result := TJWTCryptoUtils.BuildToken(Header, Payload, Signature);

    finally
      JSONObj.Free;
    end;

  except
    on E: Exception do
    begin
      AError := 'FCM JWT generate error: ' + E.Message;
      Result := '';
    end;
  end;
end;

end.
