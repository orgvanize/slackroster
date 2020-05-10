package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

const slackAPI string = "https://slack.com/api"

func main() {
	fmt.Print("Starting server...\n")

	r := mux.NewRouter()
	// TODO
	// limit request to slack.com domain
	r.HandleFunc("/listChannelEmails", listChannelEmails).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = ":8080"
	}
	panic(http.ListenAndServe(":"+port, r))
}

type Channel struct {
	ID   string
	Name string
}

type channelsResponse struct {
	Channels []Channel
}

type membersResponse struct {
	Members []string
}

type userResponse struct {
	User struct {
		Is_admin  bool
		Real_name string
		Profile   struct {
			Email string
		}
	}
}

type queryParams struct {
	key   string
	value string
}

func VerifySigningSecret(r *http.Request) ([]byte, error) {
	signingSecret := os.Getenv("SIGNING_SECRET")
	if signingSecret == "" {
		return nil, errors.New("Failed to get signing secret")
	}

	timeStampString := r.Header.Get("X-Slack-Request-Timestamp")
	slackSignature := r.Header.Get("X-Slack-Signature")

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, errors.New(("failed to read request body"))
	}
	defer r.Body.Close()

	signingBaseString := "v0:" + timeStampString + ":" + string(bodyBytes)
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(signingBaseString))
	mySignature := mac.Sum(nil)
	mySignatureString := "v0=" + hex.EncodeToString(mySignature)

	signatureValid := hmac.Equal([]byte(mySignatureString), []byte(slackSignature))
	if !signatureValid {
		return nil, errors.New("Slack request signature invalid")
	}

	return bodyBytes, nil
}

func listChannelEmails(w http.ResponseWriter, r *http.Request) {
	// verify request from slack https://api.slack.com/authentication/verifying-requests-from-slack
	_, doNotVerify := os.LookupEnv("DO_NOT_VERIFY_REQUEST")
	if !doNotVerify {
		reqBodyBytes, err := VerifySigningSecret(r)
		if err != nil {
			panic(err)
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(reqBodyBytes))
	}

	// TODO
	// check if user requesting is an admin, if not throw error

	// Request all converstions https://slack.com/api/conversations.list?types=private_channel, public_channel
	channelsBytes, err := slackAPIRequest("conversations.list?types=private_channel,public_channel",
		[]queryParams{
			{key: "types", value: "private_channel,public_channel"},
		})
	if err != nil {
		panic(err)
	}

	// From response build list of channel names and IDs
	var channelsResponse channelsResponse
	err = json.Unmarshal(channelsBytes, &channelsResponse)
	if err != nil {
		panic(err)
	}

	// Check list to see if any names match text in request, if not send text saying no channel name found
	r.ParseForm()
	requestText := r.FormValue("text")

	var channelID *string
	for _, channel := range channelsResponse.Channels {
		if channel.Name == requestText {
			channelID = &channel.ID
			break
		}
	}

	if channelID == nil {
		panic(fmt.Sprintf("channel with name %s does not exist", requestText))
	}

	// If match found, request channel members for channel ID https://slack.com/api/conversations.members?channel=G013JD99ZS8
	membersBytes, err := slackAPIRequest("conversations.members", []queryParams{
		{key: "channel", value: *channelID},
	})
	if err != nil {
		panic(err)
	}

	var membersResponse membersResponse
	err = json.Unmarshal(membersBytes, &membersResponse)
	if err != nil {
		panic(err)
	}

	// For all members found, Return list of emails
	for _, userID := range membersResponse.Members {
		userResponse := getUserInfo(userID)

		fmt.Printf("User %s\n", userResponse)
	}
}

func getUserInfo(userID string) userResponse {
	userByte, err := slackAPIRequest("users.info", []queryParams{
		{key: "user", value: userID},
	})
	if err != nil {
		panic(err)
	}

	var userResponse userResponse
	err = json.Unmarshal(userByte, &userResponse)
	if err != nil {
		panic(err)
	}

	return userResponse
}

func slackAPIRequest(endpoint string, queryParams []queryParams) ([]byte, error) {
	oAuthTokenBot := os.Getenv("OAUTH_TOKEN_BOT")
	if oAuthTokenBot == "" {
		panic("Failed to get oauth token")
	}

	req, err := http.NewRequest("GET", slackAPI+"/"+endpoint, nil)
	reqQuery := req.URL.Query()
	for _, param := range queryParams {
		reqQuery.Add(param.key, param.value)
	}
	req.URL.RawQuery = reqQuery.Encode()
	req.Header.Add("Authorization", "Bearer "+oAuthTokenBot)

	if err != nil {
		panic("Failed to form new request")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic("Failed to get resp")
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return respBytes, nil
}