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
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

const slackAPI string = "https://slack.com/api"

type SlackResponse struct {
	Response_type string
	Text          string
}

type ErrorHandler func(w http.ResponseWriter, r *http.Request) error

func errorMiddleware(h ErrorHandler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerErr := h(w, r)
		if handlerErr != nil {
			log.Printf("Error: %s", handlerErr)
			response := SlackResponse{
				Response_type: "ephemeral",
				Text:          fmt.Sprintf("Error: %s", handlerErr),
			}
			js, err := json.Marshal(response)
			if err != nil {
				log.Print("Failed to marshal json for slack response")
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
		}
	})
}

func main() {
	fmt.Print("Starting server...\n")

	r := mux.NewRouter()
	// TODO
	// limit request to slack.com domain
	r.HandleFunc("/listChannelEmails", errorMiddleware(listChannelEmails)).Methods("POST")

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

func listChannelEmails(w http.ResponseWriter, r *http.Request) error {
	// verify request from slack https://api.slack.com/authentication/verifying-requests-from-slack
	_, doNotVerify := os.LookupEnv("DO_NOT_VERIFY_REQUEST")
	if !doNotVerify {
		reqBodyBytes, err := VerifySigningSecret(r)
		if err != nil {
			return err
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(reqBodyBytes))
	}

	// check if user requesting is an admin, if not throw error
	r.ParseForm()
	requestText := r.FormValue("text")
	requestingUserID := r.FormValue("user_id")

	adminResponse, err := getUserInfo(requestingUserID)
	if err != nil {
		return err
	}
	if !adminResponse.User.Is_admin {
		return errors.New("User does not have admin access")
	}

	// Request all converstions https://slack.com/api/conversations.list?types=private_channel, public_channel
	channelsBytes, err := slackAPIRequest("conversations.list?types=private_channel,public_channel",
		[]queryParams{
			{key: "types", value: "private_channel,public_channel"},
		})
	if err != nil {
		return err
	}

	// From response build list of channel names and IDs
	var channelsResponse channelsResponse
	err = json.Unmarshal(channelsBytes, &channelsResponse)
	if err != nil {
		return err
	}

	// Check list to see if any names match text in request, if not send text saying no channel name found
	var channelID *string
	for _, channel := range channelsResponse.Channels {
		if channel.Name == requestText {
			channelID = &channel.ID
			break
		}
	}

	if channelID == nil {
		err := fmt.Errorf("channel with name %s does not exist", requestText)
		return err
	}

	// If match found, request channel members for channel ID https://slack.com/api/conversations.members?channel=G013JD99ZS8
	membersBytes, err := slackAPIRequest("conversations.members", []queryParams{
		{key: "channel", value: *channelID},
	})
	if err != nil {
		return err
	}

	var membersResponse membersResponse
	err = json.Unmarshal(membersBytes, &membersResponse)
	if err != nil {
		return err
	}

	// For all members found, Return list of emails
	for _, userID := range membersResponse.Members {
		userResponse, err := getUserInfo(userID)
		if err != nil {
			return err
		}

		fmt.Printf("User %s\n", userResponse.User.Profile)
	}

	return nil
}

func getUserInfo(userID string) (*userResponse, error) {
	userByte, err := slackAPIRequest("users.info", []queryParams{
		{key: "user", value: userID},
	})
	if err != nil {
		return nil, err
	}

	var userResponse userResponse
	err = json.Unmarshal(userByte, &userResponse)
	if err != nil {
		return nil, err
	}

	return &userResponse, nil
}

func slackAPIRequest(endpoint string, queryParams []queryParams) ([]byte, error) {
	oAuthTokenBot := os.Getenv("OAUTH_TOKEN_BOT")
	if oAuthTokenBot == "" {
		return nil, errors.New("Failed to get oauth token")
	}

	req, err := http.NewRequest("GET", slackAPI+"/"+endpoint, nil)
	reqQuery := req.URL.Query()
	for _, param := range queryParams {
		reqQuery.Add(param.key, param.value)
	}
	req.URL.RawQuery = reqQuery.Encode()
	req.Header.Add("Authorization", "Bearer "+oAuthTokenBot)

	if err != nil {
		return nil, errors.New("Failed to form new request")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Failed to get resp")
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return respBytes, nil
}
