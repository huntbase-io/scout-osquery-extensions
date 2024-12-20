package main

import "github.com/osquery/osquery-go/plugin/table"

func RemoteExecColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("script_name"),
		table.TextColumn("args"),
		table.TextColumn("console_out"),
		table.TextColumn("error_out"),
		table.TextColumn("execution_time"),
		table.TextColumn("duration"),
		table.TextColumn("script_hash"),
		table.IntegerColumn("from_cache"),
	}
}

// Columns for the table that stores the scripts that are executed at query time
func QuickExecColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("script_name"),
		table.TextColumn("args"),
		table.TextColumn("console_out"),
		table.TextColumn("error_out"),
		table.TextColumn("execution_time"),
		table.TextColumn("duration"),
		table.TextColumn("script_hash"),
		table.TextColumn("from_cache"),
		table.TextColumn("columns"),
	}
}

// Columns for the table that stores the state of cached scripts
func CachedScriptsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("description"),
		table.TextColumn("hash"),
		table.TextColumn("last_updated"),
		table.TextColumn("cache"),
		table.TextColumn("path"),
	}
}

// Columns for the scheduled scripts table
func ScheduledExecColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("description"),
		table.TextColumn("hash"),
		table.TextColumn("schedule"),
		table.TextColumn("last_run"),
		table.TextColumn("next_run"),
		table.TextColumn("cache"),
		table.TextColumn("path"),
		table.TextColumn("status"),
		table.TextColumn("args"),
	}
}

// Columns for the table that stores the script execution results
func ExecResultsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("script_name"),
		table.TextColumn("args"),
		table.TextColumn("console_out"),
		table.TextColumn("error_out"),
		table.TextColumn("execution_time"),
		table.TextColumn("duration"),
		table.TextColumn("script_hash"),
		table.TextColumn("from_cache"),
		table.TextColumn("cache"),
		table.TextColumn("timestamp"),
	}
}
