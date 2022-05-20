package aws

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/dgrijalva/jwt-go"
)

var (
	region      = "ap-northeast-1"
	endpointUrl = "http://localhost:5000"
)

type Cognito interface {
	ValidClaim(token string) (bool, error)
	Auth(email, password string) (idToken string, refreshToken string, err error)
	UpdateToken(refreshToken string) (idToken string, err error)
	SignUp(email, password string) (userSub string, err error)
	ConfirmSignUp(email, confirmationCode string) error
	ForgotPassword(email string) error
	ConfirmForgotPassword(email, confirmationCode, password string) error
	SendConfirmationCode(email string) error
	GetUser(email string) (string, error)
}

type CognitoClient struct {
	timeNow func() time.Time
	iss     string
	jwk     *jwk

	userPoolID string
	clientID   string
	svc        *cognitoidentityprovider.CognitoIdentityProvider
}

func NewCognitoClient(timeNow func() time.Time) Cognito {

	awsConfig := &aws.Config{
		Region:      aws.String(region),
		Endpoint:    aws.String(endpointUrl),
	}

	awsSession := session.Must(session.NewSession())
	svc := cognitoidentityprovider.New(awsSession, awsConfig)

	userPoolID, err := createUserPool(svc)
	if err != nil {
		panic(err)
	}

	clientID, err := createUserPoolClient(svc, userPoolID)
	if err != nil {
		panic(err)
	}

	jwk, err := newJWKs(endpointUrl, userPoolID)
	if err != nil {
		panic(err)
	}

	iss := fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v", region, userPoolID)

	return &CognitoClient{
		timeNow:    timeNow,
		iss:        iss,
		jwk:        jwk,
		userPoolID: userPoolID,
		clientID:   clientID,
		svc:        svc,
	}
}

func (c *CognitoClient) ValidClaim(token string) (bool, error) {

	claim := &claim{}
	t, err := jwt.ParseWithClaims(token, claim, c.jwk.getKeyFunc())
	if err != nil {
		return false, err
	}

	if claim.Exp < c.timeNow().Unix() {
		return false, fmt.Errorf("token is expired")
	}

	if claim.Iss != c.iss {
		return false, fmt.Errorf("token does not match issuer")
	}

	if "id" != claim.TokenUse && "access" != claim.TokenUse {
		return false, fmt.Errorf("token is id or access")
	}

	if !t.Valid {
		return false, fmt.Errorf("token is inValid")
	}

	return false, nil

}

// Auth https://docs.aws.amazon.com/ja_jp/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
func (c *CognitoClient) Auth(email, password string) (idToken string, refreshToken string, err error) {

	params := &cognitoidentityprovider.AdminInitiateAuthInput{
		AuthFlow: aws.String("ADMIN_NO_SRP_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(email),
			"PASSWORD": aws.String(password),
		},
		ClientId:   aws.String(c.clientID),
		UserPoolId: aws.String(c.userPoolID),
	}

	res, err := c.svc.AdminInitiateAuth(params)

	if err != nil {
		return "", "", err
	}

	return *res.AuthenticationResult.IdToken, *res.AuthenticationResult.RefreshToken, nil
}

// UpdateToken https://docs.aws.amazon.com/ja_jp/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html
func (c *CognitoClient) UpdateToken(refreshToken string) (idToken string, err error) {

	params := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("REFRESH_TOKEN_AUTH"),
		AuthParameters: map[string]*string{
			"REFRESH_TOKEN": aws.String(refreshToken),
		},
		ClientId: aws.String(c.clientID),
	}

	res, err := c.svc.InitiateAuth(params)
	if err != nil {
		return "", err
	}

	return *res.AuthenticationResult.IdToken, nil
}

// SignUp https://docs.aws.amazon.com/ja_jp/cognito-user-identity-pools/latest/APIReference/API_SignUp.html
func (c *CognitoClient) SignUp(email, password string) (userSub string, err error) {

	ua := &cognitoidentityprovider.AttributeType{
		Name:  aws.String("email"),
		Value: aws.String(email),
	}
	params := &cognitoidentityprovider.SignUpInput{
		Username: aws.String(email),
		Password: aws.String(password),
		ClientId: aws.String(c.clientID),
		UserAttributes: []*cognitoidentityprovider.AttributeType{
			ua,
		},
	}

	res, err := c.svc.SignUp(params)
	if err != nil {
		return "", err
	}

	return *res.UserSub, nil
}

// ConfirmSignUp https://docs.aws.amazon.com/ja_jp/cognito-user-identity-pools/latest/APIReference/API_ConfirmSignUp.html
func (c *CognitoClient) ConfirmSignUp(email, confirmationCode string) error {

	params := &cognitoidentityprovider.ConfirmSignUpInput{
		Username:         aws.String(email),
		ConfirmationCode: aws.String(confirmationCode),
		ClientId:         aws.String(c.clientID),
	}

	_, err := c.svc.ConfirmSignUp(params)
	if err != nil {
		return err
	}

	return nil
}

// ForgotPassword https://docs.aws.amazon.com/ja_jp/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
func (c *CognitoClient) ForgotPassword(email string) error {

	params := &cognitoidentityprovider.ForgotPasswordInput{
		Username: aws.String(email),
		ClientId: aws.String(c.clientID),
	}

	_, err := c.svc.ForgotPassword(params)
	if err != nil {
		return err
	}
	return nil
}

// ConfirmForgotPassword https://docs.aws.amazon.com/ja_jp/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html
func (c *CognitoClient) ConfirmForgotPassword(email, confirmationCode, password string) error {

	params := &cognitoidentityprovider.ConfirmForgotPasswordInput{
		Username:         aws.String(email),
		ConfirmationCode: aws.String(confirmationCode),
		Password:         aws.String(password),
		ClientId:         aws.String(c.clientID),
	}

	_, err := c.svc.ConfirmForgotPassword(params)
	if err != nil {
		return err
	}
	return nil
}

// SendConfirmationCode https://docs.aws.amazon.com/ja_jp/cognito-user-identity-pools/latest/APIReference/API_ResendConfirmationCode.html
func (c *CognitoClient) SendConfirmationCode(email string) error {

	params := &cognitoidentityprovider.ResendConfirmationCodeInput{
		Username: aws.String(email),
		ClientId: aws.String(c.clientID),
	}

	_, err := c.svc.ResendConfirmationCode(params)
	if err != nil {
		return err
	}

	return nil
}

// GetUser https://docs.aws.amazon.com/ja_jp/cognito-user-identity-pools/latest/APIReference/API_AdminGetUser.html
func (c *CognitoClient) GetUser(email string) (string, error) {
	params := &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(c.userPoolID),
		Username:   aws.String(email),
	}

	res, err := c.svc.AdminGetUser(params)

	for _, a := range res.UserAttributes {
		if *a.Name == "email" {
			return *a.Value, nil
		}
	}

	return "", err
}

func createUserPool(svc *cognitoidentityprovider.CognitoIdentityProvider) (userPoolID string, err error) {

	params := &cognitoidentityprovider.CreateUserPoolInput{
		PoolName: aws.String("MyUserPool"),
	}

	res, err := svc.CreateUserPool(params)
	if err != nil {
		return "", err
	}

	userPoolID = *res.UserPool.Id

	return userPoolID, nil
}

func createUserPoolClient(svc *cognitoidentityprovider.CognitoIdentityProvider, userPoolID string) (clientID string, err error) {

	params := &cognitoidentityprovider.CreateUserPoolClientInput{
		ClientName: aws.String("MyUserPoolClient"),
		UserPoolId: aws.String(userPoolID),
	}

	res, err := svc.CreateUserPoolClient(params)
	if err != nil {
		return "", err
	}

	clientID = *res.UserPoolClient.ClientId

	return clientID, nil
}

type claim struct {
	Sub           string `json:"sub"`
	EmailVerified bool   `json:"email_verified"`
	Iss           string `json:"iss"`
	UserName      string `json:"cognito:username"`
	OriginJti     string `json:"origin_jti"`
	Aud           string `json:"aud"`
	EventID       string `json:"event_id"`
	TokenUse      string `json:"token_use"`
	AuthTime      int64  `json:"auth_time"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
	Jti           string `json:"jti"`
	Email         string `json:"email"`
	jwt.MapClaims
}
