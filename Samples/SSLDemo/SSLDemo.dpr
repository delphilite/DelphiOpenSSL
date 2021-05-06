{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) 2016 Luca Minuti                                              }
{  https://bitbucket.org/lminuti/delphi-openssl                                }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");             }
{  you may not use this file except in compliance with the License.            }
{  You may obtain a copy of the License at                                     }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                              }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software         }
{  distributed under the License is distributed on an "AS IS" BASIS,           }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and         }
{  limitations under the License.                                              }
{                                                                              }
{******************************************************************************}
program SSLDemo;

uses
  Vcl.Forms,

  OpenSSL.Api_11 in '..\..\Source\OpenSSL.Api_11.pas',
  OpenSSL.Core in '..\..\Source\OpenSSL.Core.pas',
  OpenSSL.EncUtils in '..\..\Source\OpenSSL.EncUtils.pas',
  OpenSSL.RandUtils in '..\..\Source\OpenSSL.RandUtils.pas',
  OpenSSL.RSAUtils in '..\..\Source\OpenSSL.RSAUtils.pas',
  OpenSSL.SMIMEUtils in '..\..\Source\OpenSSL.SMIMEUtils.pas',

  SSLDemo.EncFrame in 'SSLDemo.EncFrame.pas' {EncFrame: TFrame},
  SSLDemo.KeyPairFrame in 'SSLDemo.KeyPairFrame.pas' {KeyPairFrame: TFrame},
  SSLDemo.MainFrame in 'SSLDemo.MainFrame.pas' {MainFrame: TFrame},
  SSLDemo.RandFrame in 'SSLDemo.RandFrame.pas' {RandomFrame: TFrame},
  SSLDemo.RSABufferFrame in 'SSLDemo.RSABufferFrame.pas' {RSABufferFrame: TFrame},
  SSLDemo.UnpackPKCS7Frame in 'SSLDemo.UnpackPKCS7Frame.pas' {UnpackPKCS7Frame: TFrame},
  SSLDemo.MainForm in 'SSLDemo.MainForm.pas' {MainForm};

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := True;
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
