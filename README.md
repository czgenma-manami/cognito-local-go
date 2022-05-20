# cognito-local-go

## 概要
cognito-localを利用した検証

## Docker
- 利用したイメージ
  - https://hub.docker.com/r/motoserver/moto
- 起動
```shell
docker-compose up -d
```

## Cognito
- 下記、検証した機能一覧

| 機能 |
| --- |
| AdminInitiateAuth |
| SignUp |
| ConfirmSignUp |
| ForgotPassword |
| ConfirmForgotPassword |
| ResendConfirmationCode |
| AdminGetUser |
