<#
    Checks .NET usage in the Folder Vault scripts against the .NET Framework 4.8
    reference assemblies (what Windows PowerShell 5.1 runs on), without Windows.

      * every [Type] named in the code exists in .NET Framework 4.8
      * every [Type]::Method(...) exists as a public static method taking that many arguments
      * every [Type]::Property / ::EnumValue exists
      * every [Type]::new(...) and New-Object Type(...) has a matching constructor
      * members called on variables created with New-Object / ::new exist on that type
      * every XAML element and attribute exists in WPF, and every member the code
        uses on a named XAML control (e.g. $c.Pw1.Clear()) exists on that control

    Usage: pwsh -File Test-FVNetFrameworkApi.ps1 -RefDir <net48 dir> -MlcDll <MetadataLoadContext.dll> -Path <files>
    Output: one object per problem (File, Line, Problem). No output = no problems found.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RefDir,
    [Parameter(Mandatory)][string]$MlcDll,
    [Parameter(Mandatory)][string[]]$Path
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Add-Type -Path $MlcDll

$dlls = @(Get-ChildItem $RefDir -Filter *.dll | ForEach-Object FullName) + @(Get-ChildItem (Join-Path $RefDir 'Facades') -Filter *.dll -ErrorAction SilentlyContinue | ForEach-Object FullName)
$resolver = New-Object System.Reflection.PathAssemblyResolver -ArgumentList (, [string[]]$dlls)
$mlc = New-Object System.Reflection.MetadataLoadContext -ArgumentList $resolver, 'mscorlib'
$byName = @{}
foreach ($d in $dlls) {
    try { $a = $mlc.LoadFromAssemblyPath($d) } catch { continue }
    try { $types = $a.GetTypes() } catch [System.Reflection.ReflectionTypeLoadException] { $types = @($_.Exception.Types | Where-Object { $_ }) }
    foreach ($t in $types) { if ($t.IsPublic -or $t.IsNestedPublic) { $byName[$t.FullName.Replace('+', '.')] = $t } }
}

# PowerShell type accelerators and PowerShell's own types (not part of .NET Framework).
$accel = @{
    'string' = 'System.String'; 'int' = 'System.Int32'; 'long' = 'System.Int64'; 'bool' = 'System.Boolean'; 'double' = 'System.Double'
    'datetime' = 'System.DateTime'; 'guid' = 'System.Guid'; 'byte' = 'System.Byte'; 'char' = 'System.Char'; 'uint32' = 'System.UInt32'
    'uint64' = 'System.UInt64'; 'int32' = 'System.Int32'; 'int64' = 'System.Int64'; 'uint16' = 'System.UInt16'; 'object' = 'System.Object'
    'array' = 'System.Array'; 'hashtable' = 'System.Collections.Hashtable'; 'regex' = 'System.Text.RegularExpressions.Regex'; 'xml' = 'System.Xml.XmlDocument'
    'void' = 'System.Void'; 'math' = 'System.Math'; 'timespan' = 'System.TimeSpan'; 'version' = 'System.Version'; 'type' = 'System.Type'
    'convert' = 'System.Convert'; 'console' = 'System.Console'; 'environment' = 'System.Environment'; 'decimal' = 'System.Decimal'; 'single' = 'System.Single'
    'ValueType' = 'System.ValueType'; 'bigint' = 'System.Numerics.BigInteger'; 'uri' = 'System.Uri'; 'ipaddress' = 'System.Net.IPAddress'; 'mailaddress' = 'System.Net.Mail.MailAddress'
    'securestring' = 'System.Security.SecureString'; 'X509Certificate' = 'System.Security.Cryptography.X509Certificates.X509Certificate'
    'wmi' = 'System.Management.ManagementObject'; 'adsi' = 'System.DirectoryServices.DirectoryEntry'; 'char[]' = 'System.Char[]'
}
$psOnly = @('pscustomobject', 'psobject', 'ordered', 'scriptblock', 'switch', 'ref', 'psvariable', 'pscredential', 'cmdletbinding', 'parameter', 'outputtype', 'validateset', 'validaterange',
    'allownull', 'allowemptystring', 'allowemptycollection', 'alias', 'supportswildcards', 'validatenotnullorempty', 'validatescript', 'pstypename', 'psmoduleinfo', 'powershell', 'runspacefactory', 'cimsession', 'ciminstance', 'NullString')

function Resolve-FVType {
    param([string]$Name)
    $n = $Name.Trim()
    if ($n.EndsWith('[]')) { $n = $n.Substring(0, $n.Length - 2) }
    $generic = $null
    if ($n -match '^([^\[]+)\[(.+)\]$') { $generic = $Matches[2]; $n = $Matches[1] }
    if ($psOnly -contains $n) { return 'PS' }
    if ($n -like 'System.Management.Automation*' -or $n -like 'Microsoft.PowerShell*' -or $n -like 'Microsoft.Management.Infrastructure*') { return 'PS' }
    if ($accel.ContainsKey($n)) { $n = $accel[$n] }
    $candidates = @($n, "System.$n")
    if ($null -ne $generic) {
        $arity = ($generic -split ',(?![^\[]*\])').Count
        $candidates = @("$n``$arity", "System.$n``$arity")
    }
    foreach ($c in $candidates) { if ($byName.ContainsKey($c)) { return $byName[$c] } }
    return $null
}

function Test-ArgCount {
    param($Methods, [int]$Count)
    foreach ($m in $Methods) {
        $ps = $m.GetParameters()
        $required = @($ps | Where-Object { -not $_.IsOptional -and -not ($_.GetCustomAttributesData() | Where-Object { $_.AttributeType.Name -eq 'ParamArrayAttribute' }) }).Count
        $hasParams = @($ps | Where-Object { $_.GetCustomAttributesData() | Where-Object { $_.AttributeType.Name -eq 'ParamArrayAttribute' } }).Count -gt 0
        if ($Count -ge $required -and ($Count -le $ps.Count -or $hasParams)) { return $true }
    }
    return $false
}

function Get-Members {
    param($Type, [string]$Name)
    $flags = [System.Reflection.BindingFlags]'Public, Instance, Static, FlattenHierarchy, IgnoreCase'
    $t = $Type
    $all = @()
    while ($null -ne $t) {
        $all += @($t.GetMembers($flags) | Where-Object { $_.Name -ieq $Name })
        $t = $t.BaseType
    }
    foreach ($i in @($Type.GetInterfaces())) { $all += @($i.GetMembers() | Where-Object { $_.Name -ieq $Name }) }
    return $all
}

$problems = New-Object System.Collections.Generic.List[object]
function Add-Problem { param([string]$File, [int]$Line, [string]$Text) $problems.Add([pscustomobject]@{ File = $File; Line = $Line; Problem = $Text }) }

# PowerShell adds these to every object; not .NET members.
$psIntrinsic = @('PSObject', 'PSTypeNames', 'Count', 'Length', 'ForEach', 'Where', 'psbase', 'psadapted', 'psextended', 'GetType', 'ToString', 'Equals', 'GetHashCode')

foreach ($file in $Path) {
    $leaf = Split-Path -Leaf $file
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errs)

    # --- type names
    foreach ($te in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] -or $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)) {
        $tn = $te.TypeName.FullName
        if ($te.TypeName -is [System.Management.Automation.Language.ArrayTypeName]) { $tn = $te.TypeName.ElementType.FullName }
        $r = Resolve-FVType $tn
        if ($null -eq $r) { Add-Problem $leaf $te.Extent.StartLineNumber "type [$tn] not found in .NET Framework 4.8" }
    }

    # --- static calls, properties, ::new
    foreach ($me in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Static -and $n.Expression -is [System.Management.Automation.Language.TypeExpressionAst] }, $true)) {
        $t = Resolve-FVType $me.Expression.TypeName.FullName
        if ($null -eq $t -or $t -eq 'PS') { continue }
        $name = $me.Member.Extent.Text
        if ($me -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            $argc = 0; if ($null -ne $me.Arguments) { $argc = $me.Arguments.Count }
            if ($name -eq 'new') {
                $ctors = @($t.GetConstructors())
                if ($t.IsValueType -and $argc -eq 0) { continue }
                if (-not (Test-ArgCount $ctors $argc)) { Add-Problem $leaf $me.Extent.StartLineNumber "[$($t.FullName)]::new with $argc argument(s): no such constructor" }
                continue
            }
            $ms = @($t.GetMethods([System.Reflection.BindingFlags]'Public, Static, FlattenHierarchy') | Where-Object { $_.Name -ieq $name })
            if ($ms.Count -eq 0) { Add-Problem $leaf $me.Extent.StartLineNumber "[$($t.FullName)]::$name : no such public static method in .NET Framework 4.8" }
            elseif (-not (Test-ArgCount $ms $argc)) { Add-Problem $leaf $me.Extent.StartLineNumber "[$($t.FullName)]::$name with $argc argument(s): no matching overload" }
        } else {
            $ok = $false
            if ($t.IsEnum) { $ok = @($t.GetFields() | Where-Object { $_.Name -ieq $name }).Count -gt 0 }
            if (-not $ok) { $ok = @(Get-Members $t $name | Where-Object { $_.MemberType -in @('Property', 'Field') }).Count -gt 0 }
            if (-not $ok) { Add-Problem $leaf $me.Extent.StartLineNumber "[$($t.FullName)]::$name : no such static property, field or enum value" }
        }
    }

    # --- New-Object TypeName (args)  and simple type inference for variables
    $varTypes = @{}
    foreach ($cmd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-Object' }, $true)) {
        $els = @($cmd.CommandElements | Select-Object -Skip 1)
        if (@($els | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -like 'Com*' }).Count -gt 0) { continue }
        $typeName = $null; $argc = -1
        for ($i = 0; $i -lt $els.Count; $i++) {
            $e = $els[$i]
            if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
                if ($e.ParameterName -like 'Type*' -and $i + 1 -lt $els.Count) { $typeName = $els[$i + 1].Extent.Text.Trim("'", '"'); $i++ }
                elseif ($e.ParameterName -like 'Arg*' -and $i + 1 -lt $els.Count) {
                    $a = $els[$i + 1]
                    if ($a -is [System.Management.Automation.Language.ArrayLiteralAst]) { $argc = $a.Elements.Count } else { $argc = -2 }
                    $i++
                }
                continue
            }
            if ($null -eq $typeName) {
                $txt = $e.Extent.Text
                if ($e -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $typeName = $e.Value }
                else { $typeName = $txt.Trim("'", '"') }
            } elseif ($argc -eq -1) {
                if ($e -is [System.Management.Automation.Language.ParenExpressionAst]) {
                    $p = $e.Pipeline.PipelineElements[0]
                    if ($p -is [System.Management.Automation.Language.CommandExpressionAst] -and $p.Expression -is [System.Management.Automation.Language.ArrayLiteralAst]) { $argc = $p.Expression.Elements.Count } else { $argc = 1 }
                } elseif ($e -is [System.Management.Automation.Language.ArrayLiteralAst]) { $argc = $e.Elements.Count }
                else { $argc = 1 }
            }
        }
        if ([string]::IsNullOrEmpty($typeName) -or $typeName -like '$*') { continue }
        $t = Resolve-FVType $typeName
        if ($null -eq $t) { Add-Problem $leaf $cmd.Extent.StartLineNumber "New-Object $typeName : type not found in .NET Framework 4.8"; continue }
        if ($t -eq 'PS') { continue }
        if ($argc -lt 0) { $argc = if ($argc -eq -1) { 0 } else { -2 } }
        if ($argc -ge 0 -and -not ($t.IsValueType -and $argc -eq 0) -and -not (Test-ArgCount @($t.GetConstructors()) $argc)) {
            Add-Problem $leaf $cmd.Extent.StartLineNumber "New-Object $typeName with $argc argument(s): no such constructor"
        }
        # remember "$x = New-Object T"
        $parent = $cmd.Parent
        while ($null -ne $parent -and -not ($parent -is [System.Management.Automation.Language.AssignmentStatementAst])) {
            if ($parent -is [System.Management.Automation.Language.StatementBlockAst] -or $parent -is [System.Management.Automation.Language.NamedBlockAst]) { $parent = $null; break }
            $parent = $parent.Parent
        }
        if ($null -ne $parent -and $parent.Left -is [System.Management.Automation.Language.VariableExpressionAst]) { $varTypes[$parent.Left.VariablePath.UserPath] = $t }
    }
    foreach ($asg in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
        $rhs = $asg.Right
        if ($rhs -is [System.Management.Automation.Language.PipelineAst] -and $rhs.PipelineElements.Count -eq 1 -and $rhs.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) { $rhs = $rhs.PipelineElements[0].Expression }
        if ($rhs -is [System.Management.Automation.Language.CommandExpressionAst]) { $rhs = $rhs.Expression }
        if ($rhs -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $rhs.Static -and $rhs.Member.Extent.Text -eq 'new' -and $rhs.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
            $t = Resolve-FVType $rhs.Expression.TypeName.FullName
            if ($null -ne $t -and $t -ne 'PS') { $varTypes[$asg.Left.VariablePath.UserPath] = $t }
        }
    }
    # Variables assigned more than one way are not checked (type unknown).
    foreach ($k in @($varTypes.Keys)) {
        $n = @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] -and $x.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $x.Left.VariablePath.UserPath -eq $k }, $true)).Count
        if ($n -gt 1) { $varTypes.Remove($k) }
    }
    foreach ($me in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and -not $n.Static -and $n.Expression -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
        $v = $me.Expression.VariablePath.UserPath
        if (-not $varTypes.ContainsKey($v)) { continue }
        $name = $me.Member.Extent.Text
        if ($psIntrinsic -contains $name -or $name -like 'Add_*' -or $name -like 'Remove_*') {
            if ($name -like 'Add_*') {
                $ev = $name.Substring(4)
                if (@(Get-Members $varTypes[$v] $ev | Where-Object { $_.MemberType -eq 'Event' }).Count -eq 0) { Add-Problem $leaf $me.Extent.StartLineNumber "`$$v ($($varTypes[$v].Name)) has no event '$ev'" }
            }
            continue
        }
        $mem = @(Get-Members $varTypes[$v] $name)
        if ($mem.Count -eq 0) { Add-Problem $leaf $me.Extent.StartLineNumber "`$$v ($($varTypes[$v].FullName)) has no member '$name'"; continue }
        if ($me -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            $argc = 0; if ($null -ne $me.Arguments) { $argc = $me.Arguments.Count }
            $ms = @($mem | Where-Object { $_.MemberType -eq 'Method' })
            if ($ms.Count -gt 0 -and -not (Test-ArgCount $ms $argc)) { Add-Problem $leaf $me.Extent.StartLineNumber "`$$v.$name with $argc argument(s): no matching overload on $($varTypes[$v].Name)" }
        }
    }

    # --- XAML
    $text = [System.IO.File]::ReadAllText($file)
    if ($text -notmatch 'XamlReader') { continue }
    $styles = [regex]::Match($text, "(?s)\`$script:Styles = @'\r?\n(.*?)\r?\n'@").Groups[1].Value
    $wpfNs = @('System.Windows', 'System.Windows.Controls', 'System.Windows.Controls.Primitives', 'System.Windows.Media', 'System.Windows.Documents', 'System.Windows.Shapes', 'System.Windows.Data', 'System.Windows.Input')
    function Get-WpfType { param([string]$Local)
        foreach ($ns in $wpfNs) { if ($byName.ContainsKey("$ns.$Local")) { return $byName["$ns.$Local"] } }
        return $null
    }
    $named = @{}
    foreach ($m in [regex]::Matches($text, "(?s)\`$script:(\w+Xaml) = @'\r?\n(.*?)\r?\n'@")) {
        [xml]$doc = $m.Groups[2].Value.Replace('<!--STYLES-->', $styles)
        $lineBase = ($text.Substring(0, $m.Index) -split "`n").Count
        foreach ($el in $doc.SelectNodes('//*')) {
            $local = $el.LocalName
            if ($el.NamespaceURI -ne 'http://schemas.microsoft.com/winfx/2006/xaml/presentation') { continue }
            if ($local.Contains('.')) {
                $owner, $prop = $local.Split('.', 2)
                $ot = Get-WpfType $owner
                if ($null -eq $ot) { Add-Problem $leaf $lineBase "XAML ($($m.Groups[1].Value)): unknown element type '$owner'" }
                elseif (@(Get-Members $ot $prop).Count -eq 0) { Add-Problem $leaf $lineBase "XAML ($($m.Groups[1].Value)): $owner has no property '$prop'" }
                continue
            }
            $t = Get-WpfType $local
            if ($null -eq $t) { Add-Problem $leaf $lineBase "XAML ($($m.Groups[1].Value)): unknown element '$local'"; continue }
            foreach ($at in $el.Attributes) {
                if ($at.Name -like 'xmlns*' -or $at.Prefix -eq 'x') {
                    if ($at.LocalName -eq 'Name' -and $at.Prefix -eq 'x') { $named[$at.Value] = $t }
                    continue
                }
                $an = $at.LocalName
                if ($an.Contains('.')) {
                    $owner, $prop = $an.Split('.', 2)
                    $ot = Get-WpfType $owner
                    $ok = $null -ne $ot -and (@(Get-Members $ot "${prop}Property").Count -gt 0 -or @(Get-Members $ot "Set$prop").Count -gt 0)
                    if (-not $ok) { Add-Problem $leaf $lineBase "XAML ($($m.Groups[1].Value)): attached property '$an' not found" }
                    continue
                }
                if (@(Get-Members $t $an | Where-Object { $_.MemberType -in @('Property', 'Event', 'Field') }).Count -eq 0) {
                    Add-Problem $leaf $lineBase "XAML ($($m.Groups[1].Value)): <$local> has no property or event '$an'"
                }
            }
            if ($local -eq 'Setter' -and $null -ne $el.ParentNode.Attributes['TargetType']) {
                $tt = $el.ParentNode.Attributes['TargetType'].Value -replace '^\{x:Type (\w+)\}$', '$1'
                $tType = Get-WpfType $tt
                $prop = $el.Attributes['Property'].Value
                if ($null -eq $tType -or @(Get-Members $tType $prop).Count -eq 0) { Add-Problem $leaf $lineBase "XAML style: $tt has no property '$prop'" }
            }
        }
    }
    # members the code uses on named controls: $c.<Name>.<Member>
    foreach ($me in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Expression -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Expression.Expression -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
        $ctl = $me.Expression.Member.Extent.Text
        if (-not $named.ContainsKey($ctl)) { continue }
        $name = $me.Member.Extent.Text
        $t = $named[$ctl]
        if ($name -like 'Add_*') {
            $ev = $name.Substring(4)
            if (@(Get-Members $t $ev | Where-Object { $_.MemberType -eq 'Event' }).Count -eq 0) { Add-Problem $leaf $me.Extent.StartLineNumber "control $ctl ($($t.Name)) has no event '$ev'" }
            continue
        }
        if ($psIntrinsic -contains $name) { continue }
        $mem = @(Get-Members $t $name)
        if ($mem.Count -eq 0) { Add-Problem $leaf $me.Extent.StartLineNumber "control $ctl ($($t.Name)) has no member '$name'"; continue }
        if ($me -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            $argc = 0; if ($null -ne $me.Arguments) { $argc = $me.Arguments.Count }
            $ms = @($mem | Where-Object { $_.MemberType -eq 'Method' })
            if ($ms.Count -gt 0 -and -not (Test-ArgCount $ms $argc)) { Add-Problem $leaf $me.Extent.StartLineNumber "control $ctl.$name with $argc argument(s): no matching overload" }
        }
    }
}
$mlc.Dispose()
$problems
