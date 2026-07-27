package arkfilechecks

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

const arkfileAuthPath = "github.com/arkfile/Arkfile/auth"

var fileCryptoSinkNames = map[string]struct{}{
	"DecryptFEK":                    {},
	"DecryptFileMetadata":           {},
	"DecryptGCM":                    {},
	"DecryptGCMWithAAD":             {},
	"DecryptMetadataWithDerivedKey": {},
	"DeriveAccountPasswordKey":      {},
	"DeriveCustomPasswordKey":       {},
	"DerivePasswordKey":             {},
	"DeriveShareKey":                {},
	"EncryptFEK":                    {},
	"EncryptGCM":                    {},
	"EncryptGCMWithAAD":             {},
	"decryptChunk":                  {},
	"decryptMetadataField":          {},
	"encryptChunk":                  {},
	"encryptMetadata":               {},
	"encryptPasswordHint":           {},
	"unwrapFEK":                     {},
	"wrapFEK":                       {},
}

var OPAQUEFileKeyAnalyzer = &analysis.Analyzer{
	Name: "arkopaquefilekey",
	Doc:  "rejects OPAQUE session and export outputs passed to file cryptography",
	Run:  runOPAQUEFileKey,
}

func runOPAQUEFileKey(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			function, ok := node.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				return true
			}

			tainted := collectOPAQUEOutputs(pass, function.Body)
			if len(tainted) == 0 && !bodyContainsExplicitOPAQUEField(function.Body) {
				return false
			}

			ast.Inspect(function.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn := calledFunction(pass, call)
				if !isFileCryptoSink(fn) {
					return true
				}
				for _, argument := range call.Args {
					if expressionUsesOPAQUEOutput(pass, argument, tainted) {
						pass.Reportf(argument.Pos(), "OPAQUE session or export material must not enter file-cryptography operations")
					}
				}
				return true
			})
			return false
		})
	}
	return nil, nil
}

func isFileCryptoSink(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	if _, ok := fileCryptoSinkNames[fn.Name()]; !ok {
		return false
	}
	switch functionPackagePath(fn) {
	case arkfileCryptoPath, "github.com/arkfile/Arkfile/cmd/arkfile-client":
		return true
	default:
		return false
	}
}

func collectOPAQUEOutputs(pass *analysis.Pass, body *ast.BlockStmt) map[types.Object]struct{} {
	tainted := make(map[types.Object]struct{})

	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Rhs) != 1 {
			return true
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := calledFunction(pass, call)
		if fn == nil || functionPackagePath(fn) != arkfileAuthPath {
			return true
		}

		var outputIndexes map[int]struct{}
		switch fn.Name() {
		case "ClientRecoverCredentials":
			outputIndexes = map[int]struct{}{0: {}, 2: {}}
		case "ClientFinalizeRegistration":
			outputIndexes = map[int]struct{}{1: {}}
		default:
			return true
		}
		for index := range outputIndexes {
			if index >= len(assignment.Lhs) {
				continue
			}
			if identifier, ok := assignment.Lhs[index].(*ast.Ident); ok {
				if object := identifierObject(pass, identifier); object != nil && identifier.Name != "_" {
					tainted[object] = struct{}{}
				}
			}
		}
		return true
	})

	changed := true
	for changed {
		changed = false
		ast.Inspect(body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for index, lhs := range assignment.Lhs {
				if len(assignment.Rhs) == 0 {
					continue
				}
				rhsIndex := index
				if rhsIndex >= len(assignment.Rhs) {
					rhsIndex = len(assignment.Rhs) - 1
				}
				if !expressionUsesOPAQUEOutput(pass, assignment.Rhs[rhsIndex], tainted) {
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

func identifierObject(pass *analysis.Pass, identifier *ast.Ident) types.Object {
	if object := pass.TypesInfo.Defs[identifier]; object != nil {
		return object
	}
	return pass.TypesInfo.Uses[identifier]
}

func expressionUsesOPAQUEOutput(pass *analysis.Pass, expression ast.Expr, tainted map[types.Object]struct{}) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if node == nil || found {
			return false
		}
		switch value := node.(type) {
		case *ast.Ident:
			if _, ok := tainted[pass.TypesInfo.Uses[value]]; ok {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if isExplicitOPAQUEField(value.Sel.Name) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func bodyContainsExplicitOPAQUEField(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok && isExplicitOPAQUEField(selector.Sel.Name) {
			found = true
			return false
		}
		return !found
	})
	return found
}

func isExplicitOPAQUEField(name string) bool {
	switch name {
	case "OPAQUEExport", "OpaqueExport", "OPAQUESessionKey":
		return true
	default:
		return false
	}
}
