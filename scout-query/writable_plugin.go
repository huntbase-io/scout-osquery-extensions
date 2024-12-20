package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/osquery/osquery-go/gen/osquery"
	"github.com/osquery/osquery-go/plugin/table"
)

// InsertFunc defines a function for inserting rows into a table
type InsertFunc func(ctx context.Context, queryContext table.QueryContext, rowId string, autoRowId bool, jsonValueArray []interface{}) ([]map[string]string, error)

// InsertablePlugin wraps the existing osquery-go table.Plugin and adds support for inserts
type InsertablePlugin struct {
	*table.Plugin
	insert InsertFunc
}

// NewInsertablePlugin creates a new insertable plugin by wrapping the existing table.Plugin
func NewInsertablePlugin(name string, columns []table.ColumnDefinition, gen table.GenerateFunc, insert InsertFunc) *InsertablePlugin {
	plugin := table.NewPlugin(name, columns, gen)
	return &InsertablePlugin{
		Plugin: plugin,
		insert: insert,
	}
}

// Call overrides the Call method to add support for the insert action
func (p *InsertablePlugin) Call(ctx context.Context, request osquery.ExtensionPluginRequest) osquery.ExtensionResponse {
	// Handle the standard "generate" (SELECT) case
	if request["action"] == "generate" {
		return p.Plugin.Call(ctx, request)
	}
	ok := osquery.ExtensionStatus{Code: 0, Message: "OK"}
	// Add support for the "insert" action
	if request["action"] == "insert" {
		queryContext, err := parseQueryContext(request["context"])
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error parsing context JSON: " + err.Error(),
				},
			}
		}
		jsonValueArray, err := parseJsonValueArray(request["json_value_array"])
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error parsing \"json_value_array\" field in JSON: " + err.Error(),
				},
			}
		}
		autoRowId, err := parseAutoRowId(request["auto_rowid"])
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error parsing \"auto_rowid\" field in JSON: " + err.Error(),
				},
			}
		}
		rowId := request["id"]

		// Execute the insert function
		data, err := p.insert(ctx, *queryContext, rowId, autoRowId, jsonValueArray)
		if err != nil {
			return osquery.ExtensionResponse{
				Status:   &ok,
				Response: []map[string]string{{"status": "failure", "message": "error inserting rows into table: " + err.Error()}},
			}
		}

		return osquery.ExtensionResponse{
			Status:   &ok,
			Response: data,
		}
	}

	// For unsupported actions, return an error
	return osquery.ExtensionResponse{
		Status: &osquery.ExtensionStatus{
			Code:    1,
			Message: "unsupported action: " + request["action"],
		},
	}
}

// Helper functions to parse JSON inputs
func parseQueryContext(ctxJSON string) (*table.QueryContext, error) {
	var parsed table.QueryContext
	err := json.Unmarshal([]byte(ctxJSON), &parsed)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseJsonValueArray(jsonValueArrayJson string) ([]interface{}, error) {
	var jsonValueArray []interface{}
	err := json.Unmarshal([]byte(jsonValueArrayJson), &jsonValueArray)
	if err != nil {
		return nil, err
	}
	return jsonValueArray, nil
}

func parseAutoRowId(autoRowIdJson string) (bool, error) {
	if autoRowIdJson != "" {
		return strconv.ParseBool(autoRowIdJson)
	}
	return false, nil
}
