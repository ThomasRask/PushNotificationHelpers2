unit FCM.Helper;

interface

uses
{$IFDEF MSWINDOWS}
  Winapi.Windows,
{$ENDIF}
  System.SysUtils, System.Classes, System.Net.HttpClient, System.Net.URLClient,
  System.DateUtils, System.JSON;

type
  TFCMHelper = class
  private
    class function GetAccessToken(const AJWT: string;
      var AError: string): string;
    class function BuildPayload(const ADeviceToken, ATitle, ABody,
      AData: string): string;
    class procedure Log(const AMsg: string);
  public
    /// <summary>
    /// Sends a push notification to an Android device using Firebase Cloud
    /// Messaging (FCM) and JWT authentication via CryptoLib4Pascal.
    /// No OpenSSL dependency.
    /// </summary>
    /// <param name="AServiceAccountJSONPath">
    ///   Path to the Firebase service account JSON key file.
    /// </param>
    /// <param name="ADeviceToken">
    ///   FCM device token of the target Android device.
    /// </param>
    /// <param name="AProjectID">
    ///   Firebase project ID associated with your app.
    /// </param>
    /// <param name="ATitle">Title of the notification.</param>
    /// <param name="ABody">Body text of the notification.</param>
    /// <param name="AData">
    ///   Custom data as JSON string (optional).
    ///   Example: '{"action":"open_screen","id":"123"}'
    /// </param>
    /// <returns>
    ///   Returns the server response as a string with HTTP status code
    ///   and response content, or an error message.
    /// </returns>
    class function SendPushNotification(
      const AServiceAccountJSONPath, ADeviceToken, AProjectID,
      ATitle, ABody: string;
      const AData: string = ''): string;
  end;

implementation

uses
  System.IOUtils, System.NetEncoding,
  FCM.JWT; 

{ TFCMHelper }

class procedure TFCMHelper.Log(const AMsg: string);
begin
{$IFDEF DEBUG}
  {$IFDEF MSWINDOWS}
  OutputDebugString(
    PChar(FormatDateTime('yyyy-mm-dd hh:nn:ss', Now) + ' [FCM] ' + AMsg)
  );
  {$ELSE}
  // Linux / macOS — output to console
  WriteLn(FormatDateTime('yyyy-mm-dd hh:nn:ss', Now) + ' [FCM] ' + AMsg);
  {$ENDIF}
{$ENDIF}
end;

class function TFCMHelper.GetAccessToken(const AJWT: string;
  var AError: string): string;
var
  HTTPClient: THTTPClient;
  Response: IHTTPResponse;
  PostData: TStringStream;
  JSONResponse: TJSONObject;
  PostBody: string;
begin
  Result := '';

  if AJWT.IsEmpty then
  begin
    AError := 'GetAccessToken: JWT is empty';
    Exit;
  end;

  HTTPClient := THTTPClient.Create;
  try
    HTTPClient.ConnectionTimeout := 10000;
    HTTPClient.ResponseTimeout   := 10000;

    // grant_type must be URL-encoded, assertion is a JWT token
    PostBody :=
      'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer' +
      '&assertion=' + TNetEncoding.URL.Encode(AJWT);

    PostData := TStringStream.Create(PostBody, TEncoding.UTF8);
    try
      Response := HTTPClient.Post(
        'https://oauth2.googleapis.com/token',
        PostData,
        nil,
        [TNetHeader.Create('Content-Type', 'application/x-www-form-urlencoded')]
      );

      if Response.StatusCode <> 200 then
      begin
        AError := Format('GetAccessToken: HTTP %d - %s',
          [Response.StatusCode, Response.ContentAsString]);
        Log(AError);
        Exit;
      end;

      JSONResponse := TJSONObject.ParseJSONValue(
        Response.ContentAsString) as TJSONObject;
      if not Assigned(JSONResponse) then
      begin
        AError := 'GetAccessToken: Unable to parse response';
        Exit;
      end;

      try
        if not JSONResponse.TryGetValue<string>('access_token', Result) then
        begin
          AError := 'access_token missing in response: ' +
            Response.ContentAsString;
          Result := '';
        end;
      finally
        JSONResponse.Free;
      end;

    finally
      PostData.Free;
    end;
  finally
    HTTPClient.Free;
  end;
end;

class function TFCMHelper.BuildPayload(const ADeviceToken, ATitle, ABody,
  AData: string): string;
var
  Notification : TJSONObject;
  Android      : TJSONObject;
  Message      : TJSONObject;
  Payload      : TJSONObject;
  DataObj      : TJSONObject;
begin
  // Notification block
  Notification := TJSONObject.Create;
  Notification.AddPair('title', ATitle);
  Notification.AddPair('body',  ABody);

  // Android specific settings
  Android := TJSONObject.Create;
  Android.AddPair('priority', 'high');

  // Message block
  Message := TJSONObject.Create;
  Message.AddPair('token',        ADeviceToken);
  Message.AddPair('notification', Notification);
  Message.AddPair('android',      Android);

  // Optional custom data
  if not AData.IsEmpty then
  begin
    DataObj := TJSONObject.ParseJSONValue(AData) as TJSONObject;
    if Assigned(DataObj) then
      Message.AddPair('data', DataObj)
    else
      Log('BuildPayload: Unable to parse custom data JSON: ' + AData);
  end;

  // All payload
  Payload := TJSONObject.Create;
  Payload.AddPair('message', Message);

  try
    Result := Payload.ToString;
    Log('Payload: ' + Result);
  finally
    Payload.Free; // also free Message, Notification, Android, DataObj
  end;
end;

class function TFCMHelper.SendPushNotification(
  const AServiceAccountJSONPath, ADeviceToken, AProjectID,
  ATitle, ABody: string;
  const AData: string): string;
var
  JWT         : string;
  AccessToken : string;
  JWTError    : string;
  AccessError : string;
  URL         : string;
  HTTPClient  : THTTPClient;
  Response    : IHTTPResponse;
  PostData    : TStringStream;
begin
  try
    // --- Input validation ---
    if not TFile.Exists(AServiceAccountJSONPath) then
    begin
      Result := 'Error: Service account JSON not found: ' +
        AServiceAccountJSONPath;
      Log(Result);
      Exit;
    end;

    if ADeviceToken.IsEmpty then
    begin
      Result := 'Error: Device token is empty';
      Log(Result);
      Exit;
    end;

    if AProjectID.IsEmpty then
    begin
      Result := 'Error: Project ID is empty';
      Log(Result);
      Exit;
    end;

    Log(Format('Send totification → token: %s, project: %s',
      [ADeviceToken, AProjectID]));

    // --- Step 1: Generate JWT using CryptoLib4Pascal ---
    JWTError := '';
    JWT := TFCM_JWT.Generate(AServiceAccountJSONPath, JWTError);
    if JWT.IsEmpty then
    begin
      Result := 'Error JWT: ' + JWTError;
      Log(Result);
      Exit;
    end;
    Log('JWT generated OK');

    // --- Step 2: Exchange JWT for Google OAuth2 access token ---
    AccessError := '';
    AccessToken := GetAccessToken(JWT, AccessError);
    if AccessToken.IsEmpty then
    begin
      Result := 'Error AccessToken: ' + AccessError;
      Log(Result);
      Exit;
    end;
    Log('Access token obtained OK');

    // --- Step 3: Send FCM notification ---
    URL := Format(
      'https://fcm.googleapis.com/v1/projects/%s/messages:send',
      [AProjectID]
    );

    HTTPClient := THTTPClient.Create;
    try
      HTTPClient.ConnectionTimeout := 10000;
      HTTPClient.ResponseTimeout   := 10000;

      PostData := TStringStream.Create(
        BuildPayload(ADeviceToken, ATitle, ABody, AData),
        TEncoding.UTF8
      );
      try
        Response := HTTPClient.Post(
          URL,
          PostData,
          nil,
          [
            TNetHeader.Create('Authorization', 'Bearer ' + AccessToken),
            TNetHeader.Create('Content-Type',  'application/json')
          ]
        );

        Result := Format('%d - %s',
          [Response.StatusCode, Response.ContentAsString]);
        Log('Server response: ' + Result);

      finally
        PostData.Free;
      end;
    finally
      HTTPClient.Free;
    end;

  except
    on E: ENetHTTPClientException do
    begin
      Result := 'HTTP Exception: ' + E.Message;
      Log(Result);
    end;
    on E: Exception do
    begin
      Result := 'Exception: ' + E.Message;
      Log(Result);
    end;
  end;
end;

end.
