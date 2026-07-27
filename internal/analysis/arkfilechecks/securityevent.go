package arkfilechecks

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

var SecurityEventAnalyzer = &analysis.Analyzer{
	Name: "arksecurityevent",
	Doc:  "rejects security-event construction and persistence outside the logging package",
	Run:  runSecurityEvent,
}

func runSecurityEvent(pass *analysis.Pass) (interface{}, error) {
	if pass.Pkg.Path() == arkfileLoggingPath {
		return nil, nil
	}

	for _, file := range pass.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.Ident:
				if isSecurityEventTypeName(pass.TypesInfo.Uses[value]) {
					pass.Reportf(value.Pos(), "construct security events through approved logging helpers")
				}
			case *ast.BasicLit:
				text, ok := stringLiteral(value)
				if !ok {
					break
				}
				normalized := strings.Join(strings.Fields(strings.ToLower(text)), " ")
				if strings.Contains(normalized, "insert into "+"security_events") {
					pass.Reportf(value.Pos(), "persist security events through approved logging helpers")
				}
			}
			return true
		})
	}
	return nil, nil
}

func isSecurityEventTypeName(object types.Object) bool {
	typeName, ok := object.(*types.TypeName)
	if !ok || typeName.Pkg() == nil {
		return false
	}
	return typeName.Pkg().Path() == arkfileLoggingPath && typeName.Name() == "SecurityEvent"
}
