package arkfilechecks

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

var RawIPAnalyzer = &analysis.Analyzer{
	Name: "arkrawip",
	Doc:  "rejects raw request IP values passed to persistent logging and audit sinks",
	Run:  runRawIP,
}

var logSinkNames = map[string]struct{}{
	"Fatal": {}, "Fatalf": {}, "Fatalln": {},
	"Panic": {}, "Panicf": {}, "Panicln": {},
	"Print": {}, "Printf": {}, "Println": {},
}

var rawIPHeaderNames = map[string]struct{}{
	"Forwarded":       {},
	"X-Arkfile-Peer":  {},
	"X-Forwarded-For": {},
	"X-Real-IP":       {},
}

func runRawIP(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			function, ok := node.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				return true
			}

			tainted := collectRawIPValues(pass, function.Body)
			ast.Inspect(function.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				for _, argument := range persistentSinkArguments(pass, call) {
					if expressionUsesRawIP(pass, argument, tainted) {
						pass.Reportf(argument.Pos(), "raw request IP must be converted to an EntityID before entering logs, security details, or audit records")
					}
				}
				return true
			})
			return false
		})
	}
	return nil, nil
}

func persistentSinkArguments(pass *analysis.Pass, call *ast.CallExpr) []ast.Expr {
	fn := calledFunction(pass, call)
	if fn == nil {
		return nil
	}
	path := functionPackagePath(fn)
	name := fn.Name()

	if path == "log" {
		if _, ok := logSinkNames[name]; ok {
			return call.Args
		}
	}

	if path == arkfileLoggingPath {
		switch name {
		case "Log":
			if len(call.Args) > 2 {
				return call.Args[2:]
			}
		case "LogSecurityEvent":
			if len(call.Args) > 4 {
				return call.Args[4:]
			}
		case "LogSecurityEventWithEntityID":
			if len(call.Args) > 2 {
				return call.Args[2:]
			}
		}
	}

	if path == "github.com/arkfile/Arkfile/database" && name == "LogUserAction" && len(call.Args) > 2 {
		return call.Args[2:]
	}
	return nil
}

func collectRawIPValues(pass *analysis.Pass, body *ast.BlockStmt) map[types.Object]struct{} {
	tainted := make(map[types.Object]struct{})
	changed := true
	for changed {
		changed = false
		ast.Inspect(body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Rhs) == 0 {
				return true
			}
			for index, lhs := range assignment.Lhs {
				rhsIndex := index
				if rhsIndex >= len(assignment.Rhs) {
					rhsIndex = len(assignment.Rhs) - 1
				}
				if !expressionUsesRawIP(pass, assignment.Rhs[rhsIndex], tainted) {
					continue
				}
				identifier, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				object := identifierObject(pass, identifier)
				if object == nil {
					continue
				}
				if _, exists := tainted[object]; !exists {
					tainted[object] = struct{}{}
					changed = true
				}
			}
			return true
		})
	}
	return tainted
}

func expressionUsesRawIP(pass *analysis.Pass, expression ast.Expr, tainted map[types.Object]struct{}) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if node == nil || found {
			return false
		}

		if identifier, ok := node.(*ast.Ident); ok {
			if _, raw := tainted[pass.TypesInfo.Uses[identifier]]; raw {
				found = true
				return false
			}
		}

		if call, ok := node.(*ast.CallExpr); ok {
			if isEntityIDConversion(pass, call) {
				return false
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
				if selector.Sel.Name == "RealIP" {
					found = true
					return false
				}
				if selector.Sel.Name == "Get" && len(call.Args) == 1 {
					if header, ok := stringLiteral(call.Args[0]); ok {
						if _, raw := rawIPHeaderNames[header]; raw {
							found = true
							return false
						}
					}
				}
			}
			if fn := calledFunction(pass, call); fn != nil && fn.Name() == "publicClientIP" {
				found = true
				return false
			}
		}

		selector, ok := node.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "RemoteAddr" {
			found = true
			return false
		}
		return true
	})
	return found
}

func isEntityIDConversion(pass *analysis.Pass, call *ast.CallExpr) bool {
	fn := calledFunction(pass, call)
	if fn == nil || functionPackagePath(fn) != arkfileLoggingPath {
		return false
	}
	switch fn.Name() {
	case "GetCompositeEntityIDForRequest", "GetOrCreateEntityID":
		return true
	default:
		return fn.Name() == "GetCompositeEntityID"
	}
}
