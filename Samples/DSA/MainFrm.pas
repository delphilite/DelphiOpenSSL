unit MainFrm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,
  OpenSSL.DSAUtils;

type
  TMainForm = class(TForm)
    btnSign: TButton;
    btnVerify: TButton;
    memSign: TMemo;
    memSrc: TMemo;
    pnlBottom: TPanel;
    splTop: TSplitter;
    procedure btnSignClick(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    FDSA: TDSAUtil;
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

uses
  OpenSSL.Core;

{ TMainForm }

procedure TMainForm.btnSignClick(Sender: TObject);
var
  R: TMemoryStream;
  S: TStream;
  D: TBytes;
begin
  S := TStringStream.Create(memSrc.Text);
  try
    R := TMemoryStream.Create;
    try
      FDSA.PrivateSign(S, R);
      SetLength(D, R.Size);
      Move(R.Memory^, Pointer(D)^, R.Size);
      D := Base64Encode(D);
      R.Position := 0;
      R.Size := Length(D);
      Move(Pointer(D)^, R.Memory^, R.Size);
      memSign.Lines.LoadFromStream(R);
    finally
      R.Free;
    end;
  finally
    S.Free;
  end;
end;

procedure TMainForm.btnVerifyClick(Sender: TObject);
var
  R: TMemoryStream;
  S: TStream;
  D: TBytes;
begin
  S := TStringStream.Create(memSrc.Text);
  try
    R := TMemoryStream.Create;
    try
      memSign.Lines.SaveToStream(R);
      SetLength(D, R.Size);
      Move(R.Memory^, Pointer(D)^, R.Size);
      D := Base64Decode(D);
      R.Position := 0;
      R.Size := Length(D);
      Move(Pointer(D)^, R.Memory^, R.Size);
      Caption := BoolToStr(FDSA.PublicVerify(S, R), True);
    finally
      R.Free;
    end;
  finally
    S.Free;
  end;
end;

procedure TMainForm.FormCreate(Sender: TObject);
begin
  FDSA := TDSAUtil.Create;
  FDSA.PublicKey.LoadFromFile('..\TestData\dsa_pub.pem');
  FDSA.PrivateKey.LoadFromFile('..\TestData\dsa_priv.pem');
end;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  FreeAndNil(FDSA);
end;

end.
