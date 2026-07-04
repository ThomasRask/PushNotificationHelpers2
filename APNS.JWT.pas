unit APNS.JWT;

{
  APNS JWT generator using CryptoLib4Pascal
  Algorithm: ES256 (ECDSA P-256 + SHA-256)
  Input: .p8 file (PEM, PKCS#8 format)
  Output: Compact JWT token

  Installing CryptoLib4Pascal:
  - GitHub: https://github.com/Xor-el/CryptoLib4Pascal
  - Just add source files to project or path
  - No OpenSSL dependency
}

interface

uses
  System.SysUtils, System.Classes, System.IOUtils, System.Math,
  ClpPrivateKeyInfoFactory, ClpIECParameters,
  JWT.CryptoLib.Utils;

type
  TAPNS_JWT = class
  private
    /// <summary>
    /// Sign data using ECDSA P-256 + SHA-256
    /// Returns a signature in R||S format (64 bytes) for JWT
    /// </summary>
    class function SignES256(const AData: TBytes;
      const APemKey: string; var AError: string): TBytes;

    /// <summary>
    /// Converts DER-encoded ECDSA signature (ASN.1) to JWT raw format R||S
    /// JWT requires exactly 64 bytes: 32 bytes R + 32 bytes S
    /// </summary>
    class function DerToRawSignature(const ADerSig: TBytes): TBytes;

  public
    /// <summary>
    /// Generates JWT for APNS
    /// </summary>
    /// <param name="AKeyID">Key ID from the Apple Developer portal (kid)</param>
    /// <param name="ATeamID">Team ID from Apple Developer account (iss)</param>
    /// <param name="AKeyPath">Path to .p8 file</param>
    /// <param name="AError">Output error message</param>
    /// <returns>JWT token or empty string on error</returns>
    class function Generate(const AKeyID, ATeamID, AKeyPath: string;
      var AError: string): string;
  end;

implementation

uses
  // CryptoLib4Pascal units
  ClpCryptoLibTypes,
  ClpIECCommon,
  ClpIAsymmetricKeyParameter,
  ClpPrivateKeyFactory,
  ClpISigner,
  ClpSignerUtilities,
  ClpSecureRandom,
  ClpISecureRandom;

{ TAPNS_JWT }

class function TAPNS_JWT.DerToRawSignature(const ADerSig: TBytes): TBytes;
var
  CurPos, RLen, SLen, RStart, SStart: Integer;
  OriginalRLen: Integer;
begin
  {
    DER ECDSA signature structure (ASN.1):
    30 [total-len]
      02 [r-len] [r-bytes]  <- R component
      02 [s-len] [s-bytes]  <- S component

    JWT needs: R (32 bytes) || S (32 bytes) = 64 bytes total
    Attention: DER may have a leading 0x00 byte (sign byte for positive numbers)
  }

  SetLength(Result, 64);
  FillChar(Result[0], 64, 0);

  // Validate SEQUENCE tag
  if (Length(ADerSig) < 2) or (ADerSig[0] <> $30) then
    raise Exception.Create('ES256 DER signature: invalid SEQUENCE tag');

  // Skip SEQUENCE header (tag + len)
  CurPos := 2;

  // INTEGER tag for R
  if ADerSig[CurPos] <> $02 then
    raise Exception.Create('ES256 DER signature: INTEGER tag expected for R');
  Inc(CurPos);

  // Length R (including any leading 0x00)
  OriginalRLen := ADerSig[CurPos];
  Inc(CurPos);

  RLen := OriginalRLen;
  RStart := CurPos;

  // If R has leading 0x00, we skip it
  if (ADerSig[RStart] = $00) and (RLen > 1) then
  begin
    Inc(RStart);
    Dec(RLen);
  end;

  // Copy R to output (right-align to 32 bytes)
  if RLen > 0 then
    Move(ADerSig[RStart + (RLen - Min(RLen, 32))],
         Result[32 - Min(RLen, 32)],
         Min(RLen, 32));

  // We move CurPos BEHIND the entire R block (we use OriginalRLen!)
  CurPos := CurPos + OriginalRLen;

  // INTEGER tag for S
  if (CurPos >= Length(ADerSig)) or (ADerSig[CurPos] <> $02) then
    raise Exception.Create(Format(
      'ES256 DER signature: expected INTEGER tag for S at position %d, found 0x%x',
      [CurPos, ADerSig[CurPos]]));
  Inc(CurPos);

  // Length S (including any leading 0x00)
  SLen := ADerSig[CurPos];
  Inc(CurPos);

  SStart := CurPos;

  // If S has leading 0x00, we skip it
  if (ADerSig[SStart] = $00) and (SLen > 1) then
  begin
    Inc(SStart);
    Dec(SLen);
  end;

  // Copy S to output (right-align to 32 bytes)
  if SLen > 0 then
    Move(ADerSig[SStart + (SLen - Min(SLen, 32))],
         Result[32 + (32 - Min(SLen, 32))],
         Min(SLen, 32));
end;

class function TAPNS_JWT.SignES256(const AData: TBytes;
  const APemKey: string; var AError: string): TBytes;
var
  KeyBytes: TBytes;
  PrivKey: IAsymmetricKeyParameter;
  Signer: ISigner;
  DerSignature: TBytes;
  Random: ISecureRandom;
begin
  Result := nil;
  try
    // 1. Read DER bytes from PEM
    KeyBytes := TJWTCryptoUtils.LoadPemBytes(APemKey);
    if Length(KeyBytes) = 0 then
    begin
      AError := 'ES256: Unable to load key from PEM';
      Exit;
    end;

    // 2. Parsing PKCS#8 private key
    //    .p8 Apple file is always PKCS#8 format
    PrivKey := TPrivateKeyFactory.CreateKey(KeyBytes);
    if not Supports(PrivKey, IECPrivateKeyParameters) then
    begin
      AError := 'ES256: The key is not an EC private key (expected P-256 from a .p8 file)';
      Exit;
    end;

    // 3. Create signer — SHA256withECDSA
    Signer := TSignerUtilities.GetSigner('SHA-256withECDSA');

    // 4. Initializing for signing
    Random := TSecureRandom.Create;
    Signer.Init(True, PrivKey);

    // 5. Forward the data for signature
    Signer.BlockUpdate(AData, 0, Length(AData));

    // 6. Generate a DER-encoded signature
    DerSignature := Signer.GenerateSignature;

    // 7. Convert DER → raw R||S for JWT
    Result := DerToRawSignature(DerSignature);

  except
    on E: Exception do
    begin
      AError := 'ES256 signing error: ' + E.Message;
      Result := nil;
    end;
  end;
end;

class function TAPNS_JWT.Generate(const AKeyID, ATeamID, AKeyPath: string;
  var AError: string): string;
var
  Header, Payload: string;
  SigningInput, Signature: TBytes;
  KeyContent: string;
  IssuedAt, Expiration: Int64;
begin
  Result := '';

  // Input validation
  if AKeyID.IsEmpty then
  begin
    AError := 'APNS JWT: AKeyID is empty';
    Exit;
  end;

  if ATeamID.IsEmpty then
  begin
    AError := 'APNS JWT: ATeamID is empty';
    Exit;
  end;

  if not TFile.Exists(AKeyPath) then
  begin
    AError := 'APNS JWT: file with key not found: ' + AKeyPath;
    Exit;
  end;

  try
    // Let's load the contents of the .p8 file
    KeyContent := TFile.ReadAllText(AKeyPath, TEncoding.UTF8);
    if KeyContent.IsEmpty then
    begin
      AError := 'APNS JWT: File with key is empty';
      Exit;
    end;

    // Timestamp
    IssuedAt := TJWTCryptoUtils.UnixNow;
    Expiration := TJWTCryptoUtils.UnixNowPlusSeconds(3600); // 1 hour

    // JWT Header (ES256)
    // alg: ES256 = ECDSA P-256 + SHA-256
    // kid: Key ID pro APNS
    Header := Format(
      '{"alg":"ES256","kid":"%s"}',
      [AKeyID]
    );

    // JWT Payload
    // iss: Team ID
    // iat: release time (Unix timestamp)
    // APNS does not require exp, but iat must be fresh (< 1 hour)
    Payload := Format(
      '{"iss":"%s","iat":%d}',
      [ATeamID, IssuedAt]
    );

    // Compile the signing input: Base64URL(header) + '.' + Base64URL(payload)
    SigningInput := TJWTCryptoUtils.BuildSigningInput(Header, Payload);

    // Sign ES256
    Signature := SignES256(SigningInput, KeyContent, AError);
    if Signature = nil then
      Exit; // AError is already set

    // Build the final JWT
    Result := TJWTCryptoUtils.BuildToken(Header, Payload, Signature);

  except
    on E: Exception do
    begin
      AError := 'APNS JWT generate error: ' + E.Message;
      Result := '';
    end;
  end;
end;

end.
