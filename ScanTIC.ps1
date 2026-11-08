<#
.SYNOPSIS
    ScanTIC - System Inventory Recopilation & Hardware/SOFTWARE Auditoria
    Módulo de Auditoría Portátil Automatizada para Equipos Informáticos (Windows/Ubuntu).

.NOTES
    Institución Destino: GERESA Lambayeque - Oficina de Centro de Sistemas e Informática (CSI).
    Autor y Arquitecto de Software: Ing. Roberto Carlos Montenegro Salazar.
    Versión: 3.7 (Corregido y Optimizado para Compilación .exe).
#>

# =========================================================================================
# 1. CONFIGURACIÓN DE IDENTIDAD Y RUTAS DINÁMICAS
# =========================================================================================
$SoftwareName = "ScanTIC"
$SoftwareVersion = "3.7.8"
$Author = "Ing. Roberto Montenegro Salazar"
$Institution = "CSI - GERESA Lambayeque"

$ScriptPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if ($ScriptPath -and (Test-Path $ScriptPath)) {
    $UsbDir = Split-Path -Parent $ScriptPath
} else {
    $UsbDir = $PSScriptRoot
}
if (-not $UsbDir -or $UsbDir -like "*System32*") { $UsbDir = ".\" }

$CsvName = "$($SoftwareName)_Master_Data.csv"
$CsvPath = Join-Path -Path $UsbDir -ChildPath $CsvName
$ReportExcelPath = Join-Path -Path $UsbDir -ChildPath "$($SoftwareName)_Reporte_Analisis.xls"

# =========================================================================================
# 1.1 MÓDULO DE AUTO-ACTUALIZACIÓN OBLIGATORIA (DESDE GITHUB)
# =========================================================================================
$VersionUrl = "https://github.com/rcarlosmontenegro-dev/ScanTIC/blob/255fae0e45503000e1707b7fc31751418ed1461d/version.txt"
$ScriptUrl  = "https://github.com/rcarlosmontenegro-dev/ScanTIC/blob/255fae0e45503000e1707b7fc31751418ed1461d/ScanTIC.exe"

Clear-Host
$BaseColor = "Cyan"
$HighlightColor = "Yellow"
$SuccessColor = "Green"
$ErrorColor = "Red"

Write-Host "=================================================================" -ForegroundColor $BaseColor
Write-Host "      GERESA LAMBAYEQUE - OFICINA DE CENTRO DE SISTEMAS DE INFORMACION (CSI)         " -ForegroundColor $HighlightColor
Write-Host "      $SoftwareName v$SoftwareVersion | Software de Auditoría | By R. Montenegro Salazar  " -ForegroundColor $SuccessColor
Write-Host "=================================================================`n" -ForegroundColor $BaseColor

Write-Host "[VERIFICACIÓN] Comprobando actualizaciones obligatorias en GitHub..." -ForegroundColor "Cyan"
try {
    $LatestVersion = (Invoke-RestMethod -Uri $VersionUrl -TimeoutSec 3 -ErrorAction Stop).Trim()
    if ($LatestVersion -and $LatestVersion -ne $SoftwareVersion) {
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show(
            "Se ha detectado una nueva versión oficial de ScanTIC ($LatestVersion).`nEl sistema se actualizará de forma obligatoria para continuar.", 
            "ScanTIC - Actualización Obligatoria", 
            [System.Windows.MessageBoxButton]::OK, 
            [System.Windows.MessageBoxImage]::Information
        )
        
        Write-Host "[INFO] Descargando actualización desde GitHub..." -ForegroundColor "Cyan"
        Invoke-WebRequest -Uri $ScriptUrl -OutFile $ScriptPath -ErrorAction Stop
        
        [System.Windows.MessageBox]::Show(
            "ScanTIC se ha actualizado exitosamente a la versión $LatestVersion.`nEl programa se reiniciará automáticamente.", 
            "Actualización Completada", 
            [System.Windows.MessageBoxButton]::OK, 
            [System.Windows.MessageBoxImage]::Information
        )
        
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$ScriptPath`""
        exit
    } else {
        Write-Host "[OK] Su versión ($SoftwareVersion) se encuentra totalmente al día." -ForegroundColor "Green"
        Start-Sleep -Seconds 1
    }
} catch {
    Write-Host "[MODO OFFLINE] Sin conexión a internet o sin acceso a GitHub. Operando con normalidad." -ForegroundColor "DarkYellow"
    Start-Sleep -Seconds 1
}

$IsWindows = $PSVersionTable.Platform -eq "Win32" -or $env:OS -like "*Windows*"
$HostName = [System.Environment]::MachineName.ToUpper().Trim()

# =========================================================================================
# 2. CAPTURA PREVIA DE RED (IP Y MAC FÍSICA LIMPIA - 100% OFFLINE)
# =========================================================================================
$IPAddress = "SIN_IP"
$MACAddress = "N/A"

if ($IsWindows) {
    $NetAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" -and $_.MediaType -ne "Virtual" -and $_.InterfaceDescription -notmatch "VPN|Virtual|Wireless|Wi-Fi|Bluetooth" }
    if (-not $NetAdapters) {
        $NetAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" -and $_.MediaType -ne "Virtual" }
    }

    foreach ($adapter in $NetAdapters) {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -notlike "127.*" }
        if ($ipConfig) {
            $IPAddress = $ipConfig.IPAddress
            $MACAddress = $adapter.MacAddress.ToUpper().Trim()
            break
        }
    }
}

# =========================================================================================
# 3. ANÁLISIS DE FACTOR DE FORMA Y HARDWARE BASE
# =========================================================================================
$PcType = "DESKTOP"
if ($IsWindows) {
    $CompSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $Chassis = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue
    $ChassisTypes = $Chassis.ChassisTypes
    if ($ChassisTypes -contains 8 -or $ChassisTypes -contains 9 -or $ChassisTypes -contains 10 -or $ChassisTypes -contains 14 -or $CompSystem.PCSystemType -eq 2) {
        $PcType = "LAPTOP"
    } else {
        $chassisName = ($Chassis.CChassisTypes -join " ").ToUpper()
        if ($chassisName -match "LAPTOP" -or $chassisName -match "NOTEBOOK" -or $chassisName -match "PORTABLE") {
            $PcType = "LAPTOP"
        }
    }

    $BIOS_Temp = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $CSP_Temp = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
    
    $RawSerial = if ($CSP_Temp.IdentifyingNumber) { $CSP_Temp.IdentifyingNumber.Trim() } elseif ($BIOS_Temp.SerialNumber) { $BIOS_Temp.SerialNumber.Trim() } else { "" }
    
    if (-not $RawSerial -or $RawSerial -match "To be filled" -or $RawSerial -match "Default String" -or $RawSerial -eq "0" -or $RawSerial -eq "None" -or $RawSerial.Length -lt 3) {
        $SeriePC_Temp = "S/N_NO_DETECTADO"
    } else {
        $SeriePC_Temp = $RawSerial.ToUpper().Trim()
    }
    
    $AutoMarca = if ($CompSystem.Manufacturer) { $CompSystem.Manufacturer.ToUpper().Trim() } else { "ADVANCE" }
    $AutoModelo = if ($CompSystem.Model) { $CompSystem.Model.ToUpper().Trim() } else { "PC_ESCRITORIO" }
} else {
    $SeriePC_Temp = "S/N_NO_DETECTADO"
    $AutoMarca = "GENÉRICO LINUX"
    $AutoModelo = "PC UBUNTU"
}

# =========================================================================================
# 4. VALIDACIÓN TRIPLE ESTRICTA (HOSTNAME + SERIE + MAC FÍSICA)
# =========================================================================================
$RegistroExistente = $null
if (Test-Path -Path $CsvPath) {
    try {
        Set-ItemProperty -Path $CsvPath -Name Attributes -Value "Normal" -ErrorAction SilentlyContinue
        $ExistingData = Import-Csv -Path $CsvPath -Delimiter ";" -ErrorAction SilentlyContinue
        
        if ($ExistingData) {
            $RegistroExistente = $ExistingData | Where-Object { $_.Nombre_PC -eq $HostName -and $_.Serie_PC -eq $SeriePC_Temp -and $_.Dirección_MAC -eq $MACAddress }
        }
    } catch { }
}

$AreaAsignada = ""
$ResponsableEquipo = ""
$FechaPecosaEquipo = "PENDIENTE_PECOSA"
$MarcaPC = $AutoMarca
$ModeloPC = $AutoModelo
$ManualMonitorOverride1 = $null
$ManualMonitorOverride2 = $null
$ManualImpresoraOverride = $null
$ManualTecladoOverride = $null
$ManualMouseOverride = $null

$SerieDefinitiva = if ($RegistroExistente -and $RegistroExistente.Serie_PC) { $RegistroExistente.Serie_PC } else { $SeriePC_Temp }
$MainboardSerieDefinitiva = if ($RegistroExistente -and $RegistroExistente.Mainboard_Serie) { $RegistroExistente.Mainboard_Serie } else { $SerieDefinitiva }

if ($RegistroExistente) {
    Write-Host "=================================================================" -ForegroundColor $HighlightColor
    Write-Host " [AVISO] EQUIPO RECONOCIDO EN BASE DE DATOS ($HostName / MAC: $MACAddress) !" -ForegroundColor $SuccessColor
    Write-Host "=================================================================" -ForegroundColor $HighlightColor
    Write-Host "  - Área / Oficina : $($RegistroExistente.Area_Ubicacion)" -ForegroundColor "Cyan"
    Write-Host "  - Responsable Equipo    : $($RegistroExistente.Responsable)" -ForegroundColor "Cyan"
    Write-Host "  - F. PECOSA/Alta : $($RegistroExistente.Fecha_Ingreso_PECOSA)" -ForegroundColor "Cyan"
    Write-Host "-----------------------------------------------------------------" -ForegroundColor $BaseColor
    
    $AreaAsignada = $RegistroExistente.Area_Ubicacion
    $ResponsableEquipo = $RegistroExistente.Responsable
    $FechaPecosaEquipo = if ($RegistroExistente.Fecha_Ingreso_PECOSA) { $RegistroExistente.Fecha_Ingreso_PECOSA } else { "PENDIENTE_PECOSA" }
    $MarcaPC = $RegistroExistente.Marca_PC
    $ModeloPC = $RegistroExistente.Modelo_PC
    $ManualMonitorOverride1 = $RegistroExistente.Monitor_1
    $ManualMonitorOverride2 = $RegistroExistente.Monitor_2
    $ManualImpresoraOverride = $RegistroExistente.Impresora_1
    $ManualTecladoOverride = $RegistroExistente.Teclado_Detectado
    $ManualMouseOverride = $RegistroExistente.Mouse_Detectado
    
    $OpcionActualizar = Read-Host "¿Desea actualizar algún componente de este equipo? [SI/NO]"
    $OpcionActualizar = $OpcionActualizar.ToUpper().Trim()

    if ($OpcionActualizar -ne "SI" -and $OpcionActualizar -ne "S") {
        Write-Host "`n[INFO] Sin cambios solicitados. Manteniendo datos actuales." -ForegroundColor $HighlightColor
        Start-Sleep -Seconds 2
    } else {
        $seguirModificando = $true
        while ($seguirModificando) {
            Write-Host "`n=================================================================" -ForegroundColor $SuccessColor
            Write-Host " MENÚ DE SELECCIÓN DIRECTA - MODIFICAR DISPOSITIVO" -ForegroundColor $HighlightColor
            Write-Host "=================================================================" -ForegroundColor $SuccessColor
            Write-Host " [1] Actualizar CPU / Mainboard / Fecha PECOSA"
            Write-Host " [2] Actualizar Monitor 1"
            Write-Host " [3] Actualizar Monitor 2"
            Write-Host " [4] Actualizar Teclado / Mouse Físico"
            Write-Host " [5] Actualizar Impresora"
            Write-Host " [6] Finalizar y continuar"
            $EleccionCampo = Read-Host "Ingrese opción [1-6]"

            switch ($EleccionCampo) {
                "1" {
                    $NuevMarca = Read-Host "   -> Nueva Marca [Actual: $MarcaPC]"
                    if ($NuevMarca) { $MarcaPC = $NuevMarca.ToUpper().Trim() }
                    $NuevModelo = Read-Host "   -> Nuevo Modelo [Actual: $ModeloPC]"
                    if ($NuevModelo) { $ModeloPC = $NuevModelo.ToUpper().Trim() }
                    $NuevSerie = Read-Host "   -> Nueva Serie [Actual: $SerieDefinitiva]"
                    if ($NuevSerie) { 
                        $SerieDefinitiva = $NuevSerie.ToUpper().Trim()
                        $MainboardSerieDefinitiva = $NuevSerie.ToUpper().Trim()
                    }
                    $NuevPecosa = Read-Host "   -> Nueva Fecha PECOSA [Actual: $FechaPecosaEquipo] (AAAA-MM-DD)"
                    if ($NuevPecosa) { $FechaPecosaEquipo = $NuevPecosa.ToUpper().Trim() }
                    Write-Host "[OK] Datos de CPU actualizados." -ForegroundColor $SuccessColor
                }
                "2" {
                    $mMan = Read-Host "   -> Marca Monitor 1"
                    $mMod = Read-Host "   -> Modelo Monitor 1"
                    $mSer = Read-Host "   -> Serie Física Monitor 1"
                    $ManualMonitorOverride1 = "[Marca: $($mMan.ToUpper()) | Modelo: $($mMod.ToUpper()) | Serie: $($mSer.ToUpper()) | Tipo: EXTERNO]"
                    Write-Host "[OK] Monitor 1 actualizado." -ForegroundColor $SuccessColor
                }
                "3" {
                    $mMan2 = Read-Host "   -> Marca Monitor 2"
                    $mMod2 = Read-Host "   -> Modelo Monitor 2"
                    $mSer2 = Read-Host "   -> Serie Física Monitor 2"
                    $ManualMonitorOverride2 = "[Marca: $($mMan2.ToUpper()) | Modelo: $($mMod2.ToUpper()) | Serie: $($mSer2.ToUpper()) | Tipo: EXTERNO]"
                    Write-Host "[OK] Monitor 2 actualizado." -ForegroundColor $SuccessColor
                }
                "4" {
                    $tIn = Read-Host "   -> Teclado Físico"
                    if ($tIn) { $ManualTecladoOverride = $tIn.ToUpper().Trim() }
                    $mIn = Read-Host "   -> Mouse Físico"
                    if ($mIn) { $ManualMouseOverride = $mIn.ToUpper().Trim() }
                    Write-Host "[OK] Periféricos actualizados." -ForegroundColor $SuccessColor
                }
                "5" {
                    $pMan = Read-Host "   -> Marca Impresora"
                    $pMod = Read-Host "   -> Modelo Impresora"
                    $pSer = Read-Host "   -> Serie Física Impresora"
                    $pTip = Read-Host "   -> Tipo Conexión (LOCAL, USB, RED)"
                    $pIp  = Read-Host "   -> IP de Red (o N/A)"
                    $ManualImpresoraOverride = "[MARCA: $($pMan.ToUpper()) | MODELO: $($pMod.ToUpper()) | SERIE: $($pSer.ToUpper()) | TIPO: $($pTip.ToUpper()) | IP: $($pIp.ToUpper())]"
                    Write-Host "[OK] Impresora actualizada." -ForegroundColor $SuccessColor
                }
                "6" { $seguirModificando = $false }
                default { Write-Host "[AVISO] Opción no válida." -ForegroundColor $ErrorColor }
            }

            if ($seguirModificando) {
                $otraVez = Read-Host "¿Desea actualizar otro componente? [SI/NO]"
                if ($otraVez.ToUpper().Trim() -ne "SI" -and $otraVez.ToUpper().Trim() -ne "S") { $seguirModificando = $false }
            }
        }
    }
} else {
    Write-Host "=================================================================" -ForegroundColor $BaseColor
    Write-Host "      CONFIGURACIÓN PATRIMONIAL Y DE UBICACIÓN (NUEVO EQUIPO)        " -ForegroundColor $HighlightColor
    Write-Host "=================================================================" -ForegroundColor $BaseColor

    $AreaAsignadaInput = Read-Host "Ingrese Área / Oficina / IPRESS (Ej: ADMISION, LOGISTICA)"
    $AreaAsignada = if (-not $AreaAsignadaInput) { "GERESA_LAMBAYEQUE" } else { $AreaAsignadaInput.ToUpper().Trim() -replace '\s+', '_' }

    $ResponsableInput = Read-Host "Ingrese Nombre del Responsable / Usuario"
    $ResponsableEquipo = if (-not $ResponsableInput) { "SIN_REGISTRO" } else { $ResponsableInput.ToUpper().Trim() }

    $PecosaInput = Read-Host "Ingrese Fecha de Ingreso Patrimonial / PECOSA [Formato: AAAA-MM-DD o ENTER para pendiente]"
    $FechaPecosaEquipo = if (-not $PecosaInput) { "PENDIENTE_PECOSA" } else { $PecosaInput.ToUpper().Trim() }

    if ($SerieDefinitiva -eq "S/N_NO_DETECTADO" -or $SerieDefinitiva -match "Default" -or $SerieDefinitiva -eq "0") {
        Write-Host "=================================================================" -ForegroundColor $ErrorColor
        Write-Host " [ALERTA] SERIE DE EQUIPO NO DETECTADA O GENÉRICA !" -ForegroundColor $HighlightColor
        Write-Host "=================================================================" -ForegroundColor $ErrorColor
        $ManualBiosSerie = Read-Host "Ingrese manualmente la SERIE FÍSICA impresa en la carcasa"
        $SerieDefinitiva = if ($ManualBiosSerie) { $ManualBiosSerie.ToUpper().Trim() } else { "S/N_NO_REGISTRADO" }
    }
    $MainboardSerieDefinitiva = $SerieDefinitiva
}

# Periféricos base según factor de forma
if ($PcType -eq "LAPTOP") {
    $TecladoManual = "TECLADO INTEGRADO (BUILT-IN)"
    $MouseManual = "TOUCHPAD INTEGRADO (SYNAPTICS/ELAN)"
    if (-not $ManualMonitorOverride1) {
        $MonitorList = @("[Marca: PANTALLA INTEGRADA | Modelo: LAPTOP DISPLAY | Serie: N/A | Tipo: INTEGRADO]")
    } else {
        $MonitorList = @($ManualMonitorOverride1)
    }
} else {
    if (-not $RegistroExistente) {
        Write-Host "`n-----------------------------------------------------------------" -ForegroundColor $BaseColor
        Write-Host " [PERIFÉRICOS DESKTOP] Verificando conexiones físicas..." -ForegroundColor $HighlightColor
        
        $UsbDevices = Get-CimInstance Win32_USBHub -ErrorAction SilentlyContinue
        $HayUsbConectado = if ($UsbDevices) { $true } else { $false }

        if ($HayUsbConectado) {
            $TecladoInput = Read-Host "Teclado USB físico (Marca/Modelo/Serie) [Enter para estándar]"
            $TecladoManual = if (-not $TecladoInput) { "TECLADO USB STANDARD [S/N: N/A]" } else { $TecladoInput.ToUpper().Trim() }

            $MouseInput = Read-Host "Mouse USB físico (Marca/Modelo/Serie) [Enter para estándar]"
            $MouseManual = if (-not $MouseInput) { "MOUSE USB STANDARD [S/N: N/A]" } else { $MouseInput.ToUpper().Trim() }
        } else {
            $TecladoManual = "TECLADO PS2/STANDARD [S/N: N/A]"
            $MouseManual = "MOUSE PS2/STANDARD [S/N: N/A]"
        }
    } else {
        $TecladoManual = if ($ManualTecladoOverride) { $ManualTecladoOverride } else { $RegistroExistente.Teclado_Detectado }
        $MouseManual = if ($ManualMouseOverride) { $ManualMouseOverride } else { $RegistroExistente.Mouse_Detectado }
    }
}

$EstadoEquipo = "OPERATIVO / AUDITADO"
Write-Host "`n[INFO] Procesando auditoría profunda de hardware y software..." -ForegroundColor $BaseColor
Start-Sleep -Seconds 1

# =========================================================================================
# 5. RECOPILACIÓN PROFUNDA (CPU, RAM, DISCOS, MONITORES, IMPRESORAS FÍSICAS)
# =========================================================================================
function Update-AuditProgress {
    param([int]$Percent, [string]$StatusMessage)
    $barLength = 30
    $filledLength = [math]::Round(($Percent / 100) * $barLength)
    $emptyLength = $barLength - $filledLength
    $line = "`r   [{0}{1}] {2,3}%  |  {3}" -f ("=" * $filledLength), ("-" * $emptyLength), $Percent, $StatusMessage
    Write-Host $line.PadRight(100) -NoNewline -ForegroundColor $SuccessColor
    Start-Sleep -Milliseconds 40
}

Update-AuditProgress -Percent 15 -StatusMessage "Analizando Sistema Operativo y CPU..."
if ($IsWindows) {
    $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $SO_Nombre = if ($OS.Caption) { $OS.Caption.Trim() } else { "WINDOWS" }
    $SO_Version = if ($OS.Version) { "v$($OS.Version)" } else { "v10" }
    $ArchOS = if ($OS.OSArchitecture) { $OS.OSArchitecture } else { "64-BIT" }
    
    $RAMCapTot = if ($CompSystem.TotalPhysicalMemory) { [math]::Round(($CompSystem.TotalPhysicalMemory / 1GB), 0) } else { 0 }

    $CPU = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
    if ($CPU -is [array]) { $CPU = $CPU[0] }
    $CPUMarca = if ($CPU.Manufacturer) { $CPU.Manufacturer.ToUpper().Trim() } else { "INTEL/AMD" }
    $CPUModelo = if ($CPU.Name) { $CPU.Name.Trim().ToUpper() } else { "PROCESADOR" }
    $CPUSerie = if ($CPU.ProcessorId) { $CPU.ProcessorId } else { "N/A" }

    if ($CPUSerie -eq "N/A" -or $CPUSerie -match "BFEBFBFF00000000" -or $CPUSerie.Length -lt 5) {
        if (-not $RegistroExistente) {
            Write-Host "`n`n[ALERTA CPU] CPU ID genérico detectado. Ingrese serie física:" -ForegroundColor $HighlightColor
            $CpuManualInput = Read-Host "Ingrese Serie física de CPU/Mainboard"
            if ($CpuManualInput) { $CPUSerie = $CpuManualInput.ToUpper().Trim() }
        }
    }

    $BaseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $MBMarca = if ($BaseBoard.Manufacturer) { $BaseBoard.Manufacturer.ToUpper().Trim() } else { "DESCONOCIDA" }
    $MBModelo = if ($BaseBoard.Product) { $BaseBoard.Product.ToUpper().Trim() } else { "DESCONOCIDA" }
    $MBSerie = $MainboardSerieDefinitiva
}

$UsersArray = @()
if ($IsWindows) {
    $Users = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
    if ($Users) { foreach ($u in $Users) { $UsersArray += $u.Name.ToUpper().Trim() } }
}
if ($UsersArray.Count -eq 0) { $UsersArray += "N/A" }

# Detección Interactiva de Monitores Múltiples con Validación Física
$MonitorList = @()
if ($PcType -eq "LAPTOP") {
    if (-not $ManualMonitorOverride1) {
        $MonitorList += "[Marca: PANTALLA INTEGRADA | Modelo: LAPTOP DISPLAY | Serie: N/A | Tipo: INTEGRADO]"
    } else {
        $MonitorList += $ManualMonitorOverride1
    }
} else {
    if ($RegistroExistente -and -not $OpcionActualizar) {
        if ($RegistroExistente.Monitor_1) { $MonitorList += $RegistroExistente.Monitor_1 }
        if ($RegistroExistente.Monitor_2) { $MonitorList += $RegistroExistente.Monitor_2 }
    } else {
        Write-Host "`n=================================================================" -ForegroundColor $HighlightColor
        Write-Host " [MONITORES] Detección y Verificación de Monitores Múltiples" -ForegroundColor $SuccessColor
        Write-Host "=================================================================" -ForegroundColor $HighlightColor
        
        $DetectedMonitors = @()
        if ($IsWindows) {
            $MonitorsWMI = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue
            if ($MonitorsWMI) {
                foreach ($mon in $MonitorsWMI) {
                    try {
                        $mfgBytes = ($mon.UserFriendlyName | Where-Object { $_ -ne 0 }) | ForEach-Object { [char]$_ }
                        $mfg = if ($mfgBytes) { (-join $mfgBytes).Trim() } else { "GENÉRICO" }
                        
                        $serBytes = ($mon.SerialNumberID | Where-Object { $_ -ne 0 }) | ForEach-Object { [char]$_ }
                        $ser = if ($serBytes) { (-join $serBytes).Trim() } else { "S/N_N/D" }

                        $DetectedMonitors += [PSCustomObject]@{
                            Marca = $mfg.ToUpper()
                            Serie = if ($ser -and $ser -ne "0" -and $ser -match "\w{2,}" -and $ser -ne "S/N_N/D") { $ser.ToUpper() } else { "NO_DETECTADO" }
                        }
                    } catch { }
                }
            }
        }

        $CantidadMonitoresInput = Read-Host "¿Cuántos monitores físicos tiene conectados este equipo? [1 o 2]"
        $CantMon = if ($CantidadMonitoresInput -match "^[12]$") { [int]$CantidadMonitoresInput } else { 1 }

        for ($i = 1; $i -le $CantMon; $i++) {
            Write-Host "`n--- Configurando Monitor $i de $CantMon ---" -ForegroundColor "Cyan"
            $autoMfg = if ($DetectedMonitors[$i-1].Marca) { $DetectedMonitors[$i-1].Marca } else { "GENÉRICO" }
            $autoSer = if ($DetectedMonitors[$i-1].Serie -and $DetectedMonitors[$i-1].Serie -ne "NO_DETECTADO") { $DetectedMonitors[$i-1].Serie } else { "" }

            $mMan = Read-Host "   -> Ingrese Marca del Monitor $i [Detectado: $autoMfg]"
            $mMarcaFinal = if ($mMan) { $mMan.ToUpper().Trim() } else { $autoMfg }

            $mMod = Read-Host "   -> Ingrese Modelo del Monitor $i (Ej: IPS 22, E2270SW)"
            $mModeloFinal = if ($mMod) { $mMod.ToUpper().Trim() } else { "MONITOR_EXTERNO" }

            if (-not $autoSer -or $autoSer -eq "NO_DETECTADO") {
                Write-Host "   [!] Advertencia: No se pudo leer la serie del Monitor $i automáticamente." -ForegroundColor $ErrorColor
                $mSerFisica = Read-Host "   -> [OBLIGATORIO] Ingrese la Serie impresa en la etiqueta física trasera"
                $mSerieFinal = if ($mSerFisica) { $mSerFisica.ToUpper().Trim() } else { "S/N_NO_REGISTRADO" }
            } else {
                Write-Host "   [OK] Serie detectada automáticamente: $autoSer" -ForegroundColor $SuccessColor
                $confirmSer = Read-Host "   -> ¿Desea mantener esta serie o corregirla con la etiqueta física? [ENTER para mantener / Ingrese nueva serie]"
                $mSerieFinal = if ($confirmSer) { $confirmSer.ToUpper().Trim() } else { $autoSer }
            }

            $MonitorList += "[Monitor_$i -> Marca: $mMarcaFinal | Modelo: $mModeloFinal | Serie: $mSerieFinal | Tipo: EXTERNO]".ToUpper()
        }
    }
}

Update-AuditProgress -Percent 45 -StatusMessage "Inspeccionando RAM detallada y Discos..."
$RAMList = @()
$DiskList = @()
if ($IsWindows) {
    $RAMModules = Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue
    foreach ($ram in $RAMModules) {
        $cap = [math]::Round(($ram.Capacity / 1GB), 2)
        $mfg = if ($ram.Manufacturer) { $ram.Manufacturer.Trim() } else { "GENÉRICO" }
        $part = if ($ram.PartNumber) { $ram.PartNumber.Trim() } else { "N/A" }
        $serRam = if ($ram.SerialNumber -and $ram.SerialNumber.Trim() -ne "" -and $ram.SerialNumber.Trim() -ne "0") { $ram.SerialNumber.Trim() } else { "S/N_INTERNO_N/A" }
        
        $formFactorCode = $ram.FormFactor
        $formFactorStr = switch ($formFactorCode) { 8 { "DIMM" } 12 { "SODIMM" } default { "DIMM" } }
        $memTypeCode = $ram.MemoryType
        $techStr = "DDR4"
        if ($memTypeCode -eq 24) { $techStr = "DDR3" }
        elseif ($memTypeCode -eq 26) { $techStr = "DDR4" }
        elseif ($memTypeCode -eq 30 -or $ram.ConfiguredClockSpeed -gt 3200) { $techStr = "DDR5" }

        $RAMList += "[Tipo: $techStr | Zócalo: $formFactorStr | Marca: $mfg | Parte: $part | Serie: $serRam | Cap: ${cap}GB]".ToUpper()
    }

    $PhysicalDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    foreach ($pDisk in $PhysicalDisks) {
        $dSizeGB = [math]::Round(($pDisk.Size / 1GB), 0)
        if ($dSizeGB -ge 230 -and $dSizeGB -le 245) { $dSizeGB = 256 }
        elseif ($dSizeGB -ge 460 -and $dSizeGB -le 500) { $dSizeGB = 512 }
        elseif ($dSizeGB -ge 900 -and $dSizeGB -le 1024) { $dSizeGB = 1000 }

        $dMfg = if ($pDisk.FriendlyName) { $pDisk.FriendlyName.Split()[0] } else { "GENÉRICO" }
        $dModel = if ($pDisk.FriendlyName) { $pDisk.FriendlyName.Trim() } else { "DISCO" }
        $dSerial = if ($pDisk.SerialNumber) { $pDisk.SerialNumber.Trim() } else { "S/N_NO_DISPONIBLE" }
        $dType = if ($pDisk.BusType) { $pDisk.BusType } else { "SATA/NVMe" }

        $DiskList += "[Tipo: $dType | Marca: $dMfg | Modelo: $dModel | Serie: $dSerial | Cap: ${dSizeGB}GB]".ToUpper()
    }
}
if ($RAMList.Count -eq 0) { $RAMList += "SIN DATOS RAM" }
if ($DiskList.Count -eq 0) { $DiskList += "SIN DISCOS" }

# Recopilación de Impresoras Físicas (Filtro anti-virtuales: XPS, PDF, Fax)
Update-AuditProgress -Percent 60 -StatusMessage "Analizando impresoras conectadas..."
$PrinterList = @()
if ($ManualImpresoraOverride) {
    $PrinterList = @($ManualImpresoraOverride)
} else {
    if ($IsWindows) {
        $AllPrinters = Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue
        foreach ($p in $AllPrinters) {
            $pName = if ($p.Name) { $p.Name.Trim().ToUpper() } else { "" }
            $pDriver = if ($p.DriverName) { $p.DriverName.Trim().ToUpper() } else { "" }
            $pPort = if ($p.PortName) { $p.PortName.Trim().ToUpper() } else { "" }

            if ($pName -match "XPS|PDF|FAX|ONENOTE|MICROSOFT PRINT|SEND TO" -or $pDriver -match "XPS|PDF|FAX|ONENOTE|MICROSOFT") {
                continue
            }

            $tipoConexion = "LOCAL"
            $ipImpresora = "N/A"

            if ($p.Network -eq $true -or $pPort -match "IP_" -or $pPort -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
                $tipoConexion = "RED"
                if ($pPort -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $ipImpresora = $Matches[1] } else { $ipImpresora = "CONFIGURADA_EN_RED" }
            } elseif ($pPort -match "USB" -or $pPort -match "DOT4") {
                $tipoConexion = "USB"
            }

            $pMarca = "GENÉRICO"
            if ($pDriver -match "HP" -or $pName -match "HP|LASERJET|DESKJET") { $pMarca = "HP" }
            elseif ($pDriver -match "EPSON" -or $pName -match "EPSON|ECOTANK") { $pMarca = "EPSON" }
            elseif ($pDriver -match "CANON" -or $pName -match "CANON") { $pMarca = "CANON" }
            elseif ($pDriver -match "BROTHER" -or $pName -match "BROTHER") { $pMarca = "BROTHER" }
            elseif ($pDriver -match "KYOCERA" -or $pName -match "KYOCERA") { $pMarca = "KYOCERA" }

            Write-Host "`n   [+] Impresora física detectada: $pName" -ForegroundColor $SuccessColor
            $ingresarSerieImpresora = Read-Host "   -> ¿Desea registrar la Serie física impresa en la carcasa de esta impresora? [SI/NO]"
            if ($ingresarSerieImpresora.ToUpper().Trim() -eq "SI" -or $ingresarSerieImpresora.ToUpper().Trim() -eq "S") {
                $pSerFisica = Read-Host "      Ingrese el número de serie físico"
                $pSerialFinal = if ($pSerFisica) { $pSerFisica.ToUpper().Trim() } else { "S/N_NO_REGISTRADO" }
            } else {
                $pSerialFinal = "S/N_NO_REGISTRADO"
            }

            $PrinterList += "[MARCA: $pMarca | MODELO: $pName | SERIE: $pSerialFinal | TIPO: $tipoConexion | IP: $ipImpresora]"
        }
    }
}
if ($PrinterList.Count -eq 0) { $PrinterList += "SIN IMPRESORAS FÍSICAS CONECTADAS" }

Update-AuditProgress -Percent 75 -StatusMessage "Filtrando IP v4 de red física limpia..."
if ($IsWindows) {
    $IPAddress = "SIN_IP"
    $MACAddress = "N/A"

    $NetAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" -and $_.MediaType -ne "Virtual" -and $_.InterfaceDescription -notmatch "VPN|Virtual|Wireless|Wi-Fi|Bluetooth" }
    if (-not $NetAdapters) {
        $NetAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" -and $_.MediaType -ne "Virtual" }
    }

    foreach ($adapter in $NetAdapters) {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -notlike "127.*" }
        if ($ipConfig) {
            $IPAddress = $ipConfig.IPAddress
            $MACAddress = $adapter.MacAddress.ToUpper().Trim()
            break
        }
    }
}

$Keyboards = $TecladoManual
$Mice = $MouseManual

# =========================================================================================
# 6. FILTRADO INTELIGENTE DE SOFTWARE
# =========================================================================================
Update-AuditProgress -Percent 90 -StatusMessage "Filtrando software instalado..."
$AppsArray = @()
if ($IsWindows) {
    $UninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($keyPath in $UninstallKeys) {
        if (Test-Path $keyPath) {
            $subKeys = Get-ChildItem -Path $keyPath -ErrorAction SilentlyContinue
            foreach ($sub in $subKeys) {
                try {
                    $name = $sub.GetValue("DisplayName")
                    $ver = $sub.GetValue("DisplayVersion")
                    $sys = $sub.GetValue("SystemComponent")
                    if ($name -and $sys -ne 1) {
                        if ($name -notmatch "^KB\d{6}" -and $name -notmatch "Security Update" -and $name -notmatch "Microsoft Visual C\+\+") {
                            $appCleanName = if ($ver) { "$name (v$ver)".ToUpper().Trim() } else { "$name".ToUpper().Trim() }
                            if ($AppsArray -notcontains $appCleanName) { $AppsArray += $appCleanName }
                        }
                    }
                } catch { }
            }
        }
    }
}
if ($AppsArray.Count -eq 0) { $AppsArray += "SIN SOFTWARE ADICIONAL DETECTADO" }

# =========================================================================================
# 7. GENERACIÓN DUAL DE CÓDIGOS QR
# =========================================================================================
Update-AuditProgress -Percent 98 -StatusMessage "Generando QRs organizados..."
$FechaActualStr = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")

$MonitorResumenQR = $MonitorList -join " | "
$DiscoResumenQR = $DiskList -join " | "
$RamResumenQR = $RAMList -join " | "

$QrStickerString = @"
GERESA LAMBAYEQUE - CSI
PC: $HostName
AREA: $AreaAsignada
RESP: $ResponsableEquipo
SERIE: $SerieDefinitiva
IP: $IPAddress
MAC: $MACAddress
RAM: ${RAMCapTot}GB
"@

$QrActaString = @"
=================???????????=======================
   GERESA LAMBAYEQUE - SCANTIC v$SoftwareVersion
============================???????????============
[ 📍 UBICACIÓN DE EQUIPO Y USUARIO ]
• Área / IPRESS : $AreaAsignada
• Responsable   : $ResponsableEquipo
• Hostname      : $HostName ($PcType)
• F. PECOSA     : $FechaPecosaEquipo

[ 💻 MONITORES Y CPU ]
• Monitores     : $MonitorResumenQR
• Marca / Model : $MarcaPC $ModeloPC
• Serie CPU/PC  : $SerieDefinitiva

[ 🧠 MEMORIA Y ALMACENAMIENTO ]
• RAM Total     : ${RAMCapTot} GB
• Detalle RAM   : $RamResumenQR
• Almacenamiento: $DiscoResumenQR

[ 🌐 RED Y SISTEMA ]
• IPv4 Física   : $IPAddress
• MAC Address   : $MACAddress
• Estado        : $EstadoEquipo
• Fecha Audit   : $FechaActualStr
========================================
"@

$BaseFolder = Join-Path -Path $UsbDir -ChildPath "Etiquetas_QR_Generadas"
$FolderStickers = Join-Path -Path $BaseFolder -ChildPath "Etiquetas_Sticker_Equipos"
$FolderActas = Join-Path -Path $BaseFolder -ChildPath "Etiquetas_Actas_Sistin"

if (-not (Test-Path $FolderStickers)) { New-Item -ItemType Directory -Path $FolderStickers | Out-Null }
if (-not (Test-Path $FolderActas)) { New-Item -ItemType Directory -Path $FolderActas | Out-Null }

$SafeArea = $AreaAsignada -replace '[\\/:*?"<>| ]', '_'
$SafeHost = $HostName -replace '[\\/:*?"<>| ]', '_'
$SafeUser = $ResponsableEquipo -replace '[\\/:*?"<>| ]', '_'
$SafeType = $PcType -replace '[\\/:*?"<>| ]', '_'

$FileName = "$SafeArea`_$SafeHost`_$SafeUser`_$SafeType.png"
$PathSticker = Join-Path -Path $FolderStickers -ChildPath $FileName
$PathActa = Join-Path -Path $FolderActas -ChildPath $FileName

if (Test-Path $PathSticker) { Remove-Item $PathSticker -Force -ErrorAction SilentlyContinue }
if (Test-Path $PathActa) { Remove-Item $PathActa -Force -ErrorAction SilentlyContinue }

try {
    Add-Type -AssemblyName System.Web
    $EncSticker = [System.Web.HttpUtility]::UrlEncode($QrStickerString)
    (New-Object System.Net.WebClient).DownloadFile("https://quickchart.io/qr?text=$EncSticker&size=300&margin=1", $PathSticker)

    $EncActa = [System.Web.HttpUtility]::UrlEncode($QrActaString)
    (New-Object System.Net.WebClient).DownloadFile("https://quickchart.io/qr?text=$EncActa&size=350&margin=1", $PathActa)
} catch { }

# =========================================================================================
# 8. ESTRUCTURACIÓN Y ESCRITURA EN MATRIZ MAESTRA (CSV BLINDADO + REPORTE EXCEL DE ANÁLISIS)
# =========================================================================================
Update-AuditProgress -Percent 100 -StatusMessage "Guardando en matriz CSV y generando Reporte Excel..."

$ReportProps = [ordered]@{
    'Fecha_Auditoria'       = $FechaActualStr
    'Fecha_Ingreso_PECOSA'  = $FechaPecosaEquipo
    'Tipo_Equipo'           = $PcType
    'Area_Ubicacion'        = $AreaAsignada
    'Responsable Equipo'           = $ResponsableEquipo
    'Nombre_PC'             = $HostName
    'Marca_PC'              = $MarcaPC
    'Modelo_PC'             = $ModeloPC
    'Serie_PC'              = $SerieDefinitiva
    'Estado_Equipo'         = $EstadoEquipo
    'Sistema_Operativo'     = $SO_Nombre
    'Versión_SO'            = $SO_Version.ToUpper()
    'Arquitectura_OS'       = $ArchOS.ToUpper()
}

for ($i = 0; $i -lt $UsersArray.Count; $i++) { $ReportProps["Usuario_Local_$($i + 1)"] = $UsersArray[$i] }

$ReportProps['CPU_Marca']  = $CPUMarca
$ReportProps['CPU_Modelo'] = $CPUModelo
$ReportProps['CPU_Serie']  = $CPUSerie
$ReportProps['Mainboard_Marca']  = $MBMarca
$ReportProps['Mainboard_Modelo'] = $MBModelo
$ReportProps['Mainboard_Serie']  = $MBSerie
$ReportProps['RAM_Total_GB']     = $RAMCapTot

for ($i = 0; $i -lt $RAMList.Count; $i++) { $ReportProps["RAM_Modulo_$($i + 1)"] = $RAMList[$i] }
for ($i = 0; $i -lt $DiskList.Count; $i++) { $ReportProps["Disco_Unidad_$($i + 1)"] = $DiskList[$i] }
for ($i = 0; $i -lt $MonitorList.Count; $i++) { $ReportProps["Monitor_$($i + 1)"] = $MonitorList[$i] }
for ($i = 0; $i -lt $PrinterList.Count; $i++) { $ReportProps["Impresora_$($i + 1)"] = $PrinterList[$i] }

$ReportProps['Dirección_IP']  = $IPAddress
$ReportProps['Dirección_MAC'] = $MACAddress
$ReportProps['Teclado_Detectado'] = $Keyboards
$ReportProps['Mouse_Detectado']   = $MouseManual

for ($i = 0; $i -lt $AppsArray.Count; $i++) { $ReportProps["Software_Usuario_$($i + 1)"] = $AppsArray[$i] }

$ReportProps['Desarrollador_Autor'] = $Author.ToUpper()
$ReportProps['Institución_Titular'] = $Institution.ToUpper()
$ReportProps['Motor_Auditoria'] = "$SoftwareName v$SoftwareVersion".ToUpper()

$NewObject = [PSCustomObject]$ReportProps

function Write-SafeCsvFinal {
    param([PSCustomObject]$NewObj, [string]$Path, [string]$ExcelReportPath)
    $ExistingRows = @()

    if (Test-Path -Path $Path) {
        Set-ItemProperty -Path $Path -Name Attributes -Value "Normal" -ErrorAction SilentlyContinue
        try {
            $Imported = Import-Csv -Path $Path -Delimiter ";" -ErrorAction SilentlyContinue
            if ($Imported) {
                foreach ($row in $Imported) {
                    if (-not ($row.Nombre_PC -eq $NewObj.Nombre_PC -and $row.Serie_PC -eq $NewObj.Serie_PC -and $row.Dirección_MAC -eq $NewObj.Dirección_MAC)) {
                        $ExistingRows += $row
                    }
                }
            }
        } catch { }
    }

    $ExistingRows += $NewObj
    
    $AllKeys = [ordered]@{}
    foreach ($k in $NewObj.psobject.properties.name) { $AllKeys[$k] = $true }
    foreach ($row in $ExistingRows) {
        foreach ($prop in $row.psobject.properties.name) { $AllKeys[$prop] = $true }
    }
    
    $FinalHeaders = $AllKeys.Keys
    $NormalizedRows = foreach ($row in $ExistingRows) {
        $ht = [ordered]@{}
        foreach ($fh in $FinalHeaders) {
            $val = $row.$fh
            if ($null -eq $val) { $val = "" }
            $ht[$fh] = $val
        }
        [PSCustomObject]$ht
    }

    # 1. Guardar CSV maestro limpio y blindado (ReadOnly)
    $NormalizedRows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Set-ItemProperty -Path $Path -Name Attributes -Value "ReadOnly" -ErrorAction SilentlyContinue

    # 2. Respaldo histórico automático con fecha/hora en carpeta oculta
    $HistoricoDir = Join-Path -Path $UsbDir -ChildPath "Historial_Respaldos_CSI"
    if (-not (Test-Path $HistoricoDir)) { New-Item -ItemType Directory -Path $HistoricoDir | Out-Null }
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $BackupHistoricoPath = Join-Path -Path $HistoricoDir -ChildPath "Master_Backup_$Timestamp.csv"
    Copy-Item -Path $Path -Destination $BackupHistoricoPath -Force -ErrorAction SilentlyContinue

    # 3. Exportar Reporte de Análisis en formato compatible con Excel (.xls)
    try {
        $NormalizedRows | ConvertTo-Html -Property Fecha_Auditoria, Fecha_Ingreso_PECOSA, Tipo_Equipo, Area_Ubicacion, Responsable, Nombre_PC, Marca_PC, Modelo_PC, Serie_PC, RAM_Total_GB, Dirección_IP, Dirección_MAC | Out-File -FilePath $ExcelReportPath -Encoding UTF8
    } catch { }
}

try {
    Write-SafeCsvFinal -NewObj $NewObject -Path $CsvPath -ExcelReportPath $ReportExcelPath
    Write-Host "`n`n=================================================================" -ForegroundColor Green
    Write-Host "[100% COMPLETADO] AUDITORÍA GUARDADA Y FINALIZADA EXITOSAMENTE!" -ForegroundColor Yellow
    Write-Host "Archivo CSV Maestro : $CsvPath (Protegido / ReadOnly)" -ForegroundColor Cyan
    Write-Host "Reporte de Análisis : $ReportExcelPath (Listo para tablas y Excel)" -ForegroundColor Green
    Write-Host "Stickers y Actas    : $FolderStickers" -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green
} catch {
    Write-Host "`n[COMPLETADO] Registro guardado correctamente." -ForegroundColor Green
}

Start-Sleep -Seconds 4