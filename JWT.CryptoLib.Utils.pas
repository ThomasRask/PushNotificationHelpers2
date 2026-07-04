unit JWT.CryptoLib.Utils;

interface

uses
  System.SysUtils, System.Classes, System.NetEncoding, System.DateUtils,
  ClpIECCommon,
  ClpICipherParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpISigner,
  ClpECDsaSigner,
  ClpRsaDigestSigner,
  ClpIDigest,
  ClpPemReader,
  ClpIPemObject,
  ClpSignerUtilities,
  ClpPrivateKeyFactory,
  ClpIAsymmetricKeyParameter;

type
  TJWTCryptoUtils = class
  public
    /// <summary>
    /// Base64URL encode (RFC 4648) — no padding, URL-safe characters
    /// </summary>
    class function Base64UrlEncode(const ABytes: TBytes): string; overload;
    class function Base64UrlEncode(const AText: string): string; overload;

    /// <summary>
    /// Base64URL decode
    /// </summary>
    class function Base64UrlDecode(const AText: string): TBytes;

    /// <summary>
    /// Builds the JWT header.payload part as bytes for signature
    /// </summary>
    class function BuildSigningInput(const AHeader, APayload: string): TBytes;

    /// <summary>
    /// Reads PEM key as bytes (removes header/footer/newlines)
    /// </summary>
    class function LoadPemBytes(const APemContent: string): TBytes;

    /// <summary>
    /// Builds the final JWT token
    /// </summary>
    class function BuildToken(const AHeader, APayload: string;
      const ASignature: TBytes): string;

    /// <summary>
    /// Returns the current Unix timestamp (seconds since 1/1/1970)
    /// </summary>
    class function UnixNow: Int64;
    class function UnixNowPlusSeconds(ASeconds: Int64): Int64;
  end;

implementation

{ TJWTCryptoUtils }

class function TJWTCryptoUtils.Base64UrlEncode(const ABytes: TBytes): string;
var
  Encoder: TBase64Encoding;
  B64: string;
begin
  // We create an encoder WITHOUT line breaks (0 = no line breaks)
  Encoder := TBase64Encoding.Create(0);
  try
    B64 := Encoder.EncodeBytesToString(ABytes);
  finally
    Encoder.Free;
  end;

  // Base64 › Base64URL
  Result := B64.Replace('+', '-', [rfReplaceAll])
               .Replace('/', '_', [rfReplaceAll])
               .TrimRight(['=']);
end;

class function TJWTCryptoUtils.Base64UrlEncode(const AText: string): string;
begin
  Result := Base64UrlEncode(TEncoding.UTF8.GetBytes(AText));
end;

class function TJWTCryptoUtils.Base64UrlDecode(const AText: string): TBytes;
var
  B64: string;
  Padding: Integer;
begin
  // Back to standard Base64
  B64 := AText.Replace('-', '+', [rfReplaceAll])
               .Replace('_', '/', [rfReplaceAll]);

  // We will add padding
  Padding := Length(B64) mod 4;
  if Padding = 2 then
    B64 := B64 + '=='
  else if Padding = 3 then
    B64 := B64 + '=';

  Result := TNetEncoding.Base64.DecodeStringToBytes(B64);
end;

class function TJWTCryptoUtils.BuildSigningInput(const AHeader,
  APayload: string): TBytes;
var
  Input: string;
begin
  // JWT signing input = Base64URL(header) + '.' + Base64URL(payload)
  Input := Base64UrlEncode(AHeader) + '.' + Base64UrlEncode(APayload);
  Result := TEncoding.UTF8.GetBytes(Input);
end;

class function TJWTCryptoUtils.LoadPemBytes(const APemContent: string): TBytes;
var
  Lines: TStringList;
  B64Content: TStringBuilder;
  Line, Trimmed: string;
  InBlock: Boolean;
begin
  Lines := TStringList.Create;
  B64Content := TStringBuilder.Create;
  try
    Lines.Text := APemContent;
    InBlock := False;

    for Line in Lines do
    begin
      Trimmed := Line.Trim;

      // Skip blank lines
      if Trimmed.IsEmpty then
        Continue;

      // Detecting the beginning of a PEM block
      if Trimmed.StartsWith('-----BEGIN') then
      begin
        InBlock := True;
        Continue;
      end;

      // End of PEM block detection
      if Trimmed.StartsWith('-----END') then
      begin
        InBlock := False;
        Continue;
      end;

      // Collect Base64 content
      if InBlock then
        B64Content.Append(Trimmed);
    end;

    // Decode Base64 (standard, not URL-safe)
    Result := TNetEncoding.Base64.DecodeStringToBytes(B64Content.ToString);
  finally
    Lines.Free;
    B64Content.Free;
  end;
end;

class function TJWTCryptoUtils.BuildToken(const AHeader, APayload: string;
  const ASignature: TBytes): string;
begin
  Result := Base64UrlEncode(AHeader) + '.' +
            Base64UrlEncode(APayload) + '.' +
            Base64UrlEncode(ASignature);
end;

class function TJWTCryptoUtils.UnixNow: Int64;
begin
  Result := DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now));
end;

class function TJWTCryptoUtils.UnixNowPlusSeconds(ASeconds: Int64): Int64;
begin
  Result := UnixNow + ASeconds;
end;

end.
