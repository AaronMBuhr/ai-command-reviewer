# Test-only: print a script's top-level parameter names and every function it
# defines, as JSON, by parsing it (nothing is run).
param([string]$Path)
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
$params = @()
if ($null -ne $ast.ParamBlock) { $params = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) }
$functions = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
               ForEach-Object { $_.Name })
[Console]::Out.Write((ConvertTo-Json -Compress -InputObject ([ordered]@{ params = $params; functions = $functions })))
