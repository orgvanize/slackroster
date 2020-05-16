package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/pkg/errors"

	"github.com/gorilla/mux"
)

const slackAPI string = "https://slack.com/api"

type BlockText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type Block struct {
	Type string    `json:"type"`
	Text BlockText `json:"text"`
}

type SlackResponse struct {
	Response_type string  `json:"response_type"`
	Text          string  `json:"text"`
	Blocks        []Block `json:"blocks"`
}

type ErrorHandler func(w http.ResponseWriter, r *http.Request) ([]byte, error)

func errorMiddleware(h ErrorHandler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsByte, handlerErr := h(w, r)
		w.Header().Set("Content-Type", "application/json")

		if handlerErr != nil {
			// http.Error(w, error.Error(handlerErr), http.StatusBadRequest)
			log.Printf("Error: %s", handlerErr)

			response := SlackResponse{
				Response_type: "ephemeral",
				Text:          fmt.Sprintf("Error: %s", handlerErr),
			}
			js, err := json.Marshal(response)
			if err != nil {
				log.Print("Failed to marshal json for slack response")
			}

			w.Write(js)
			return
		}

		w.Write(jsByte)
	})
}

func main() {
	fmt.Print("Starting server...\n")

	r := mux.NewRouter()
	// TODO
	// limit request to slack.com domain
	r.HandleFunc("/listChannelEmails", errorMiddleware(listChannelEmails)).Methods("POST")
	r.HandleFunc("/channelJoin", errorMiddleware(channelJoin)).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	httpErr := http.ListenAndServe(":"+port, r)
	if httpErr != nil {
		log.Fatal(fmt.Sprintf("failed to bind to port %v: %v", port, httpErr))
	}
}

type Channel struct {
	ID   string
	Name string
}

type channelsResponse struct {
	Channels []Channel
}

type channelResponse struct {
	Channel Channel
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

type Event struct {
	Type    string
	User    string
	Channel string
}

type eventRequest struct {
	Challenge string
	Token     string
	Event     Event
}

type eventType string

const memberJoinedChannel eventType = "member_joined_channel"

func channelJoin(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	w.Header().Set("Content-type", "application/json")

	var req eventRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode channel join request")
	}

	// write 200 response

	jsonStream := `{"challenge": "` + req.Challenge + `"}`
	encoder := json.NewEncoder(w)
	encoder.Encode(jsonStream)

	if req.Token != os.Getenv("VERIFICATION_TOKEN") {
		return nil, errors.New("Request token does not match verification token")
	}

	channelBytes, err := slackAPIRequest("conversations.info", []queryParams{
		{key: "channel", value: req.Event.Channel},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get channel info for id (%s)", req.Event.Channel)
	}

	var channelResponse channelResponse
	err = json.Unmarshal(channelBytes, &channelResponse)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal json for for channel response")
	}

	joinedUser, err := getUserInfo(req.Event.User)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user info for id (%s)", req.Event.User)
	}

	log.Print(channelResponse.Channel.Name)
	log.Print(joinedUser.User.Profile.Email)
	// send username and channel name to GS script

	return nil, nil
}

func verifySigningSecret(r *http.Request) ([]byte, error) {
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

func listChannelEmails(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	// verify request from slack https://api.slack.com/authentication/verifying-requests-from-slack
	_, doNotVerify := os.LookupEnv("DO_NOT_VERIFY_REQUEST")
	if !doNotVerify {
		reqBodyBytes, err := verifySigningSecret(r)
		if err != nil {
			return nil, err
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(reqBodyBytes))
	}

	// check if user requesting is an admin, if not throw error
	r.ParseForm()
	requestText := r.FormValue("text")
	requestingUserID := r.FormValue("user_id")

	adminResponse, err := getUserInfo(requestingUserID)
	if err != nil {
		return nil, err
	}
	if !adminResponse.User.Is_admin {
		return nil, errors.New("User does not have admin access")
	}

	// Request all converstions https://slack.com/api/conversations.list?types=private_channel, public_channel
	channelsBytes, err := slackAPIRequest("conversations.list?types=private_channel,public_channel",
		[]queryParams{
			{key: "types", value: "private_channel,public_channel"},
		})
	if err != nil {
		return nil, err
	}

	// From response build list of channel names and IDs
	var channelsResponse channelsResponse
	err = json.Unmarshal(channelsBytes, &channelsResponse)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	// If match found, request channel members for channel ID https://slack.com/api/conversations.members?channel=G013JD99ZS8
	membersBytes, err := slackAPIRequest("conversations.members", []queryParams{
		{key: "channel", value: *channelID},
	})
	if err != nil {
		return nil, err
	}

	var membersResponse membersResponse
	err = json.Unmarshal(membersBytes, &membersResponse)
	if err != nil {
		return nil, err
	}

	// For all members found, Return list of emails
	var users []userResponse
	for _, userID := range membersResponse.Members {
		userResponse, err := getUserInfo(userID)
		if err != nil {
			return nil, err
		}

		if userResponse.User.Profile.Email != "" {
			users = append(users, *userResponse)
		}
	}

	var usersString string
	for _, user := range users {
		usersString += user.User.Profile.Email + "\n"
	}

	response := SlackResponse{
		Response_type: "ephemeral",
		Blocks: []Block{
			{
				Type: "section",
				Text: BlockText{
					Type: "mrkdwn",
					Text: "```" + usersString + "```",
				},
			},
		},
		Text: usersString,
	}

	js, err := json.Marshal(response)
	if err != nil {
		log.Print("Failed to marshal json for slack response")
	}

	return js, nil
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

type slackApiResponse struct {
	Ok      bool
	Error   string
	Warning string
}

func slackAPIRequest(endpoint string, queryParams []queryParams) ([]byte, error) {
	oAuthTokenBot := os.Getenv("OAUTH_TOKEN_BOT")
	if oAuthTokenBot == "" {
		return nil, errors.New("Failed to get oauth token")
	}

	req, err := http.NewRequest("GET", slackAPI+"/"+endpoint, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build slack api request to endpoint (%s)", endpoint)
	}
	reqQuery := req.URL.Query()
	for _, param := range queryParams {
		reqQuery.Add(param.key, param.value)
	}
	req.URL.RawQuery = reqQuery.Encode()
	req.Header.Add("Authorization", "Bearer "+oAuthTokenBot)

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

	var apiResponse slackApiResponse
	err = json.Unmarshal(respBytes, &apiResponse)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal json for slack api request response")
	}
	if apiResponse.Ok != true {
		return nil, errors.New(apiResponse.Error)
	}

	if apiResponse.Warning != "" {
		log.Printf("warning for request to endpoint (%s): %s", endpoint, apiResponse.Warning)
	}

	return respBytes, nil
}
