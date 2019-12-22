package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

func notifySlack(config *slackConfig, zoneName string, serial uint32, diff string) error {
	if config.WebhookURL == "" {
		return nil
	}
	data := map[string]interface{}{
		"channel":    config.Channel,
		"username":   config.Name,
		"icon_emoji": config.IcomEmoji,
		"icon_url":   config.IconURL,
		"attachments": []interface{}{
			map[string]interface{}{
				"fallback": fmt.Sprintf("%s	is updated.", zoneName),
				"color": "#36a64f",
				"title": "DNS zone update notification",
				"fields": []interface{}{
					map[string]interface{}{
						"title": "Zone",
						"value": zoneName,
						"short": true,
					},
					map[string]interface{}{
						"title": "Serial",
						"value": fmt.Sprintf("%d", serial),
						"short": true,
					},
					map[string]interface{}{
						"title": "Timestamp",
						"value": time.Now().Format(time.RFC3339),
						"short": false,
					},
					map[string]interface{}{
						"title": "Diff",
						"value": diff,
						"short": false,
					},
				},
			},
		},
	}
	input, err := json.Marshal(data)
	if err != nil {
		return err
	}
	resp, err := http.Post(config.WebhookURL, "application/json", bytes.NewBuffer(input))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("invaild statuscode: %d", resp.StatusCode)
		}
		return fmt.Errorf("received error: %s", b)
	}
	return nil
}
