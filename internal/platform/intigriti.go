package platform

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

type Intigriti struct {
	api *apiClient
}

func NewIntigriti(client *http.Client, base, token string) *Intigriti {
	return &Intigriti{api: newAPIClient(client, base, func(request *http.Request) {
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
	})}
}

func (client *Intigriti) Name() string { return "intigriti" }

type intigritiEnum struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

type intigritiProgram struct {
	ID        string        `json:"id"`
	Handle    string        `json:"handle"`
	Name      string        `json:"name"`
	Following bool          `json:"following"`
	Status    intigritiEnum `json:"status"`
	Type      intigritiEnum `json:"type"`
	MinBounty struct {
		Value float64 `json:"value"`
	} `json:"minBounty"`
	MaxBounty struct {
		Value float64 `json:"value"`
	} `json:"maxBounty"`
	WebLinks struct {
		Detail string `json:"detail"`
	} `json:"webLinks"`
}

type intigritiDetail struct {
	intigritiProgram
	Domains struct {
		ID      string `json:"id"`
		Content []struct {
			ID          string        `json:"id"`
			Type        intigritiEnum `json:"type"`
			Endpoint    string        `json:"endpoint"`
			Tier        intigritiEnum `json:"tier"`
			Description string        `json:"description"`
		} `json:"content"`
	} `json:"domains"`
	Rules *struct {
		Content *struct {
			Description string `json:"description"`
			SafeHarbour bool   `json:"safeHarbour"`
			Testing     struct {
				AutomatedTooling *int   `json:"automatedTooling"`
				UserAgent        string `json:"userAgent"`
				RequestHeader    string `json:"requestHeader"`
			} `json:"testingRequirements"`
		} `json:"content"`
	} `json:"rulesOfEngagement"`
}

func (client *Intigriti) Programs(ctx context.Context) ([]Program, error) {
	const limit = 500
	offset := 0
	var programs []Program
	for {
		var page struct {
			MaxCount int                `json:"maxCount"`
			Records  []intigritiProgram `json:"records"`
		}
		path := "/v1/programs?limit=" + strconv.Itoa(limit) + "&offset=" + strconv.Itoa(offset)
		if err := client.api.get(ctx, path, &page); err != nil {
			return nil, err
		}
		for _, item := range page.Records {
			program, err := client.program(ctx, item)
			if err != nil {
				return nil, fmt.Errorf("carregando programa %s: %w", item.Handle, err)
			}
			programs = append(programs, program)
		}
		offset += len(page.Records)
		if len(page.Records) == 0 || page.MaxCount > 0 && offset >= page.MaxCount || page.MaxCount == 0 && len(page.Records) < limit {
			break
		}
	}
	return programs, nil
}

func (client *Intigriti) program(ctx context.Context, overview intigritiProgram) (Program, error) {
	var detail intigritiDetail
	if err := client.api.get(ctx, "/v1/programs/"+url.PathEscape(overview.ID), &detail); err != nil {
		return Program{}, err
	}
	program := Program{
		Platform: client.Name(), ID: detail.ID, Handle: detail.Handle, Name: detail.Name,
		State: detail.Status.Value, URL: detail.WebLinks.Detail,
		Bounty: overview.MinBounty.Value > 0 || overview.MaxBounty.Value > 0,
	}
	for _, item := range detail.Domains.Content {
		asset := NormalizeAsset(item.Endpoint, item.Type.Value)
		asset.ID = item.ID
		asset.Eligible = true
		asset.Severity = item.Tier.Value
		asset.Instruction = item.Description
		asset.Bounty = program.Bounty
		program.Assets = append(program.Assets, asset)
	}
	if !testingOpen(detail.Status.Value) {
		for index := range program.Assets {
			program.Assets[index].Eligible = false
		}
	}
	if detail.Rules != nil && detail.Rules.Content != nil {
		content := detail.Rules.Content
		program.Rules.Description = content.Description
		program.Rules.SafeHarbour = content.SafeHarbour
		program.Rules.UserAgent = content.Testing.UserAgent
		program.Rules.RequestHeader = content.Testing.RequestHeader
		if content.Testing.AutomatedTooling != nil {
			program.Rules.AutomatedTooling = *content.Testing.AutomatedTooling
		}
	}
	return program, nil
}
