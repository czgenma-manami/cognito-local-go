package main

import (
	"fmt"
	"time"

	"github.com/czgenma-manami/cognito-local-go/aws"
)

func main() {

	c := aws.NewCognitoClient(time.Now().UTC)

	email := "user@exmple.com"
	password := "password"
	confirmationCode := "123456"

	userSub, err := c.SignUp(email, password)
	if err != nil {
		fmt.Printf("signUp:%s\n", err.Error())
		panic(err)
	}
	fmt.Printf("userSub:%s\n", userSub)

	err = c.ConfirmSignUp(email, confirmationCode)
	if err != nil {
		fmt.Printf("signUp:%s\n", err.Error())
		panic(err)
	}

	idToken, refreshToken, err := c.Auth(email, password)
	if err != nil {
		fmt.Printf("auth:%s\n", err.Error())
		panic(err)
	}
	fmt.Printf("[before] id_token:%s\n", idToken)

	ok, err := c.ValidClaim(idToken)
	if err != nil {
		fmt.Printf("validClaim:%s\n", err.Error())
		panic(err)
	}
	fmt.Printf("validClaim:%v\n", ok)

	newIdToken, err := c.UpdateToken(refreshToken)
	if err != nil {
		fmt.Printf("updateToken:%s\n", err.Error())
		panic(err)
	}
	fmt.Printf("[after] id_token:%s\n", newIdToken)

	userEmail, err := c.GetUser(email)
	if err != nil {
		fmt.Printf("getUser:%s\n", err.Error())
		panic(err)
	}
	fmt.Printf("email:%s\n", userEmail)

	err = c.ForgotPassword(email)
	if err != nil {
		fmt.Printf("forgotPassword:%s\n", err.Error())
		panic(err)
	}

	err = c.ConfirmForgotPassword(email, confirmationCode, password)
	if err != nil {
		fmt.Printf("confirmForgotPassword:%s\n", err.Error())
		panic(err)
	}

	err = c.SendConfirmationCode(email)
	if err != nil {
		fmt.Printf("sendConfirmationCode:%s\n", err.Error())
		panic(err)
	}

}
