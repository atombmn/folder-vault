<#
    Finds ".Count" uses that break under Windows PowerShell 5.1 with
    Set-StrictMode -Version 3: there, .Count on a single object or on $null
    throws "The property 'Count' cannot be found on this object".
    PowerShell 7 allows it, so ordinary tests on PowerShell 7 never notice.

    A use is SAFE when the thing counted is certainly a collection:
      * @( ... )                                    array expression
      * a variable whose every assignment is @(...), @{...}, [ordered]@{...},
        New-Object of a List/Dictionary/Stack/Queue/ArrayList/HashSet, .ToArray(),
        or += onto one of those
      * a parameter declared with an array type ([string[]], [object[]], ...)
        or [hashtable]
      * .Keys / .Values / .Vaults (List) / known collection members
      * explicitly marked safe with a trailing comment:  # count-safe: <reason>
    Everything else is reported.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string[]]$Path)

$safeMembers = @('Keys', 'Values', 'Vaults', 'Problems', 'Warnings', 'Missing', 'Mismatched', 'Items', 'Groups', 'Access', 'Files', 'Parameters', 'Extensions', 'EnhancedKeyUsages')
$collectionNew = 'List|Dictionary|Stack|Queue|ArrayList|HashSet|Hashtable|ObservableCollection'

function Test-SafeRhs {
    param($Rhs)
    $e = $Rhs
    if ($e -is [System.Management.Automation.Language.CommandExpressionAst]) { $e = $e.Expression }
    elseif ($e -is [System.Management.Automation.Language.PipelineAst] -and $e.PipelineElements.Count -eq 1 -and $e.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) { $e = $e.PipelineElements[0].Expression }
    elseif ($e -is [System.Management.Automation.Language.PipelineAst] -and $e.PipelineElements.Count -eq 1 -and $e.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst]) {
        $c = $e.PipelineElements[0]
        if ($c.GetCommandName() -eq 'New-Object' -and $c.Extent.Text -match $collectionNew) { return $true }
        return $false
    }
    while ($e -is [System.Management.Automation.Language.ConvertExpressionAst]) {
        if ($e.Type.TypeName.Name -match '\[\]$|ordered|hashtable') { return $true }
        $e = $e.Child
    }
    if ($e -is [System.Management.Automation.Language.ArrayExpressionAst]) { return $true }
    if ($e -is [System.Management.Automation.Language.HashtableAst]) { return $true }
    if ($e -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $e.Member.Extent.Text -in @('ToArray', 'new')) { return $true }
    return $false
}

$findings = New-Object System.Collections.Generic.List[object]
foreach ($file in $Path) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    $lines = [System.IO.File]::ReadAllLines($file)
    $uses = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and -not $n.Static -and $n.Member.Extent.Text -eq 'Count' }, $true)
    foreach ($u in $uses) {
        $line = $lines[$u.Extent.StartLineNumber - 1]
        if ($line -match '#\s*count-safe') { continue }
        $target = $u.Expression
        while ($target -is [System.Management.Automation.Language.ParenExpressionAst]) {
            $inner = $target.Pipeline
            if ($inner -is [System.Management.Automation.Language.PipelineAst] -and $inner.PipelineElements.Count -eq 1 -and $inner.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) { $target = $inner.PipelineElements[0].Expression } else { break }
        }
        $safe = $false
        if ($target -is [System.Management.Automation.Language.ArrayExpressionAst]) { $safe = $true }
        elseif ($target -is [System.Management.Automation.Language.MemberExpressionAst] -and $target.Member.Extent.Text -in $safeMembers) { $safe = $true }
        elseif ($target -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $name = $target.VariablePath.UserPath -replace '^(script|global|local):', ''
            # Search the enclosing function (or the file) for assignments and parameter declarations.
            $scope = $u.Parent
            while ($null -ne $scope -and -not ($scope -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and -not ($scope -is [System.Management.Automation.Language.ScriptBlockAst] -and $null -eq $scope.Parent)) { $scope = $scope.Parent }
            if ($null -eq $scope) { $scope = $ast }
            $roots = @($scope)
            if ($target.VariablePath.UserPath -like 'script:*') { $roots = @($ast) }
            $assigns = @(); $params = @()
            foreach ($r in $roots) {
                $assigns += @($r.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and (($n.Left.VariablePath.UserPath -replace '^(script|global|local):', '') -eq $name) }, $true))
                $assigns += @($r.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.ConvertExpressionAst] -and $n.Left.Child -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.Left.Child.VariablePath.UserPath -eq $name }, $true))
                $params += @($r.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] -and $n.Name.VariablePath.UserPath -eq $name }, $true))
            }
            $okParam = @($params | Where-Object { $_.StaticType.IsArray -or $_.StaticType -eq [hashtable] -or $_.StaticType.Name -match 'List|Dictionary' }).Count -gt 0
            $plain = @($assigns | Where-Object { $_.Operator -eq 'Equals' })
            $okAssign = $plain.Count -gt 0 -and @($plain | Where-Object {
                    $lhsTyped = $_.Left -is [System.Management.Automation.Language.ConvertExpressionAst] -and $_.Left.Type.TypeName.Name -match '\[\]$'
                    -not ($lhsTyped -or (Test-SafeRhs $_.Right))
                }).Count -eq 0
            $foreachVar = @($scope.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] -and $n.Variable.VariablePath.UserPath -eq $name }, $true)).Count -gt 0
            if ($okParam -and $plain.Count -eq 0) { $safe = $true }
            elseif ($okAssign -and -not $foreachVar) { $safe = $true }
        }
        if (-not $safe) {
            $findings.Add([pscustomobject]@{ File = (Split-Path -Leaf $file); Line = $u.Extent.StartLineNumber; Code = $u.Extent.Text })
        }
    }
}
$findings
