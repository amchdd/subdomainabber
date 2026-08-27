package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type Bugcrowd struct {
	api *apiClient
}

func NewBugcrowd(client *http.Client, base, token string) *Bugcrowd {
	api := newAPIClient(client, base, func(request *http.Request) {
		request.Header.Set("Accept", "application/vnd.bugcrowd+json")
		request.Header.Set("Authorization", "Token "+token)
	})
	api.wait = apiPacer(base, "api.bugcrowd.com", 60)
	return &Bugcrowd{api: api}
}

func (client *Bugcrowd) Name() string { return "bugcrowd" }

type resourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type bugcrowdRelation struct {
	Data  json.RawMessage `json:"data"`
	Links json.RawMessage `json:"links"`
}

type bugcrowdResource struct {
	Type       string                      `json:"type"`
	ID         string                      `json:"id"`
	Attributes json.RawMessage             `json:"attributes"`
	Relations  map[string]bugcrowdRelation `json:"relationships"`
}

type bugcrowdPage struct {
	Data     []bugcrowdResource `json:"data"`
	Included []bugcrowdResource `json:"included"`
	Links    pageLinks          `json:"links"`
}

func (client *Bugcrowd) Programs(ctx context.Context) ([]Program, error) {
	query := url.Values{}
	query.Set("page[limit]", "100")
	query.Set("page[offset]", "0")
	query.Set("include", "current_brief.target_groups.targets,current_brief.target_groups.reward_range")
	query.Set("fields[program]", "name,code,current_brief")
	query.Set("fields[program_brief]", "target_groups")
	query.Set("fields[target_group]", "name,in_scope,targets,reward_range")
	query.Set("fields[target]", "name,uri,category")
	path := "/programs?" + query.Encode()
	var programs []Program
	seen := make(map[string]struct{})
	for path != "" {
		if err := visitPage(seen, path); err != nil {
			return nil, err
		}
		var page bugcrowdPage
		if err := client.api.get(ctx, path, &page); err != nil {
			return nil, err
		}
		index := resourceIndex(page.Included)
		for _, item := range page.Data {
			program, err := client.program(ctx, item, index)
			if err != nil {
				return nil, err
			}
			programs = append(programs, program)
		}
		path = page.Links.Next
	}
	return programs, nil
}

func (client *Bugcrowd) program(ctx context.Context, item bugcrowdResource, index map[string]bugcrowdResource) (Program, error) {
	var attributes struct {
		Name  string `json:"name"`
		Code  string `json:"code"`
		State string `json:"state"`
	}
	_ = json.Unmarshal(item.Attributes, &attributes)
	program := Program{
		Platform: client.Name(), ID: item.ID, Handle: attributes.Code, Name: attributes.Name,
		URL: "https://bugcrowd.com/" + attributes.Code,
	}
	briefRefs := refs(item.Relations["current_brief"].Data)
	if len(briefRefs) == 0 {
		return program, nil
	}
	brief, found := index[refKey(briefRefs[0])]
	if !found {
		return program, nil
	}
	assetsByID := make(map[string]Asset)
	for _, groupRef := range refs(brief.Relations["target_groups"].Data) {
		group, found := index[refKey(groupRef)]
		if !found {
			continue
		}
		assets, err := client.groupAssets(ctx, group, index)
		if err != nil {
			return Program{}, fmt.Errorf("carregando grupo %s: %w", group.ID, err)
		}
		for _, asset := range assets {
			current, found := assetsByID[asset.ID]
			if found {
				current.Eligible = current.Eligible || asset.Eligible
				current.Bounty = current.Bounty || asset.Bounty
				current.Group = mergeGroupNames(current.Group, asset.Group)
				assetsByID[asset.ID] = current
				continue
			}
			assetsByID[asset.ID] = asset
		}
	}
	keys := make([]string, 0, len(assetsByID))
	for id := range assetsByID {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		program.Assets = append(program.Assets, assetsByID[id])
	}
	for _, asset := range program.Assets {
		program.Bounty = program.Bounty || asset.Bounty
	}
	if !testingOpen(attributes.State) {
		for index := range program.Assets {
			program.Assets[index].Eligible = false
		}
	}
	return program, nil
}

func mergeGroupNames(left, right string) string {
	if left == "" || left == right {
		return right
	}
	if right == "" {
		return left
	}
	groups := strings.Split(left, ", ")
	for _, group := range groups {
		if group == right {
			return left
		}
	}
	groups = append(groups, right)
	sort.Strings(groups)
	return strings.Join(groups, ", ")
}

func (client *Bugcrowd) groupAssets(ctx context.Context, group bugcrowdResource, index map[string]bugcrowdResource) ([]Asset, error) {
	var attributes struct {
		Name    string `json:"name"`
		InScope *bool  `json:"in_scope"`
	}
	_ = json.Unmarshal(group.Attributes, &attributes)
	eligible := true
	if attributes.InScope != nil {
		eligible = *attributes.InScope
	}
	bounty := len(refs(group.Relations["reward_range"].Data)) > 0
	relation := group.Relations["targets"]
	targets := make(map[string]bugcrowdResource)
	for _, reference := range refs(relation.Data) {
		if target, found := index[refKey(reference)]; found {
			targets[target.ID] = target
		}
	}
	if path := relatedPath(relation.Links); path != "" {
		loaded, err := client.targets(ctx, path)
		if err != nil {
			return nil, err
		}
		for _, target := range loaded {
			targets[target.ID] = target
		}
	}
	assets := make([]Asset, 0, len(targets))
	for _, target := range targets {
		var targetAttributes struct {
			Name     string `json:"name"`
			URI      string `json:"uri"`
			Category string `json:"category"`
		}
		_ = json.Unmarshal(target.Attributes, &targetAttributes)
		value := strings.TrimSpace(targetAttributes.URI)
		if value == "" {
			value = targetAttributes.Name
		}
		asset := NormalizeAsset(value, targetAttributes.Category)
		asset.ID = target.ID
		asset.Eligible = eligible
		asset.Bounty = bounty
		asset.Group = attributes.Name
		assets = append(assets, asset)
	}
	return assets, nil
}

func (client *Bugcrowd) targets(ctx context.Context, path string) ([]bugcrowdResource, error) {
	var targets []bugcrowdResource
	seen := make(map[string]struct{})
	for path != "" {
		if err := visitPage(seen, path); err != nil {
			return nil, err
		}
		var page bugcrowdPage
		if err := client.api.get(ctx, path, &page); err != nil {
			return nil, err
		}
		targets = append(targets, page.Data...)
		path = page.Links.Next
	}
	return targets, nil
}

func resourceIndex(resources []bugcrowdResource) map[string]bugcrowdResource {
	index := make(map[string]bugcrowdResource, len(resources))
	for _, resource := range resources {
		index[resource.Type+":"+resource.ID] = resource
	}
	return index
}

func refs(data json.RawMessage) []resourceRef {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var many []resourceRef
	if json.Unmarshal(data, &many) == nil {
		return many
	}
	var one resourceRef
	if json.Unmarshal(data, &one) == nil && one.ID != "" {
		return []resourceRef{one}
	}
	return nil
}

func refKey(reference resourceRef) string {
	return reference.Type + ":" + reference.ID
}

func relatedPath(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var links struct {
		Related json.RawMessage `json:"related"`
	}
	if json.Unmarshal(data, &links) != nil {
		return ""
	}
	var path string
	if json.Unmarshal(links.Related, &path) == nil {
		return path
	}
	var related struct {
		Href string `json:"href"`
	}
	_ = json.Unmarshal(links.Related, &related)
	return related.Href
}
