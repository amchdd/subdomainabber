package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

type HackerOne struct {
	api *apiClient
}

func NewHackerOne(client *http.Client, base, username, token string) *HackerOne {
	return &HackerOne{api: newAPIClient(client, base, func(request *http.Request) {
		request.Header.Set("Accept", "application/json")
		request.SetBasicAuth(username, token)
	})}
}

func (client *HackerOne) Name() string { return "hackerone" }

type hackerOneProgram struct {
	ID         json.RawMessage `json:"id"`
	Attributes struct {
		Handle          string `json:"handle"`
		Name            string `json:"name"`
		State           string `json:"state"`
		SubmissionState string `json:"submission_state"`
		OffersBounties  bool   `json:"offers_bounties"`
	} `json:"attributes"`
}

type hackerOneScope struct {
	ID         json.RawMessage `json:"id"`
	Attributes struct {
		AssetType             string  `json:"asset_type"`
		AssetIdentifier       string  `json:"asset_identifier"`
		EligibleForBounty     bool    `json:"eligible_for_bounty"`
		EligibleForSubmission bool    `json:"eligible_for_submission"`
		Instruction           *string `json:"instruction"`
		MaxSeverity           string  `json:"max_severity"`
	} `json:"attributes"`
}

func (client *HackerOne) Programs(ctx context.Context) ([]Program, error) {
	path := "/v1/hackers/programs?page[number]=1&page[size]=100"
	var programs []Program
	for path != "" {
		var page struct {
			Data  []hackerOneProgram `json:"data"`
			Links pageLinks          `json:"links"`
		}
		if err := client.api.get(ctx, path, &page); err != nil {
			return nil, err
		}
		for _, item := range page.Data {
			assets, err := client.scopes(ctx, item.Attributes.Handle)
			if err != nil {
				return nil, fmt.Errorf("carregando escopo de %s: %w", item.Attributes.Handle, err)
			}
			state := item.Attributes.State
			if item.Attributes.SubmissionState != "" {
				state += "/" + item.Attributes.SubmissionState
			}
			if !testingOpen(item.Attributes.SubmissionState) {
				for index := range assets {
					assets[index].Eligible = false
				}
			}
			programs = append(programs, Program{
				Platform: client.Name(), ID: rawID(item.ID), Handle: item.Attributes.Handle,
				Name: item.Attributes.Name, State: state, URL: "https://hackerone.com/" + item.Attributes.Handle,
				Bounty: item.Attributes.OffersBounties, Assets: assets,
			})
		}
		path = page.Links.Next
	}
	return programs, nil
}

func (client *HackerOne) scopes(ctx context.Context, handle string) ([]Asset, error) {
	base := "/v1/hackers/programs/" + url.PathEscape(handle) + "/structured_scopes"
	path := base + "?page[number]=1&page[size]=100"
	var assets []Asset
	cursor := ""
	for path != "" {
		var page struct {
			Data  []hackerOneScope `json:"data"`
			Links pageLinks        `json:"links"`
		}
		if err := client.api.get(ctx, path, &page); err != nil {
			return nil, err
		}
		for _, item := range page.Data {
			asset := NormalizeAsset(item.Attributes.AssetIdentifier, item.Attributes.AssetType)
			asset.ID = rawID(item.ID)
			asset.Eligible = item.Attributes.EligibleForSubmission
			asset.Bounty = item.Attributes.EligibleForBounty
			asset.Severity = item.Attributes.MaxSeverity
			if item.Attributes.Instruction != nil {
				asset.Instruction = *item.Attributes.Instruction
			}
			assets = append(assets, asset)
		}
		path = page.Links.Next
		if path == "" && len(page.Data) == 100 {
			nextCursor := rawID(page.Data[len(page.Data)-1].ID)
			if nextCursor != "" && nextCursor != cursor {
				cursor = nextCursor
				path = base + "?filter[id__gt]=" + url.QueryEscape(cursor) + "&page[size]=100"
			}
		}
	}
	return assets, nil
}

func rawID(value json.RawMessage) string {
	text := string(value)
	if unquoted, err := strconv.Unquote(text); err == nil {
		return unquoted
	}
	return text
}
