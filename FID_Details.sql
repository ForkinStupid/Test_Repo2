SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED


--Hi

IF OBJECT_ID('VRAT.dbo.FID_Details', 'U') IS NOT NULL
DROP TABLE VRAT.dbo.FID_Details
SELECT * INTO VRAT.dbo.FID_Details 

FROM (

SELECT 
faultlineid,
[Risk Rating],
CVE,
MSFTID,
MSKBID,
Name,
description,
observation,
recommendation,
addeddate, 
Patch_Type,
Product,
Solution_Category,
Patched,
HIP,
VSE,
TP_DC,
TP_INT,
basescorevalue, 
BaseExploitabilityValue, 
BaseImpactValue,
Exploitability_Rating,
Exploit_Potential,
MVM_Exploitability,
Mitigation_Value_Server,
Mitigation_Value_WKS,
Priority_Score_Server,
Priority_Score_WKS,
/* Priority Score Data */
CAST(
CASE 
WHEN ((BaseExploitabilityValue + BaseScoreValue + BaseImpactValue) * Mitigation_Value_server) >= 100 THEN 'High' 
WHEN ((BaseExploitabilityValue + BaseScoreValue + BaseImpactValue) * Mitigation_Value_server) >= 50 THEN 'Medium' 
ELSE 'Low' 
END as nvarchar(64)) Remediation_Priority_Server,
CAST(
CASE 
WHEN ((BaseExploitabilityValue + BaseScoreValue + BaseImpactValue) * Mitigation_Value_wks) >= 100 THEN 'High' 
WHEN ((BaseExploitabilityValue + BaseScoreValue + BaseImpactValue) * Mitigation_Value_wks) >= 50 THEN 'Medium' 
ELSE 'Low' 
END as nvarchar(64)) Remediation_Priority_wks
FROM (
SELECT *, 
CASE
WHEN (BaseExploitabilityValue_PRI + BaseScoreValue_PRI + BaseImpactValue_PRI) = 0 THEN Mitigation_Value_server
ELSE ((BaseExploitabilityValue_PRI + BaseScoreValue_PRI + BaseImpactValue_PRI) * Mitigation_Value_server) 
END Priority_Score_Server,
CASE
WHEN (BaseExploitabilityValue_PRI + BaseScoreValue_PRI + BaseImpactValue_PRI) = 0 THEN  Mitigation_Value_wks
ELSE ((BaseExploitabilityValue_PRI + BaseScoreValue_PRI + BaseImpactValue_PRI) * Mitigation_Value_wks) 
END Priority_Score_WKS
FROM (
SELECT
vln.faultlineid,
CASE 
WHEN BaseScoreValue < 4 THEN 'Low' 
WHEN BaseScoreValue >= 4 AND BaseScoreValue < 7 THEN 'Medium' 
WHEN BaseScoreValue >= 7 THEN 'High' 
ELSE 'Informational' 
END [Risk Rating], 
CVE,
MSFTID,
MSKBID,
Name,
description,
observation,
recommendation,
addeddate, 
CAST(
case
when name  like '(MS%' OR name  like 'Microsoft%' OR name  like '%DirectAccess%' OR name  like '%Microsoft Windows%' then 'Microsoft Windows OS'
when name  like '%Slackware%Linux%' or name  like '%SUSE%SLE%' or name  like '%SUSE%Linux%' or name  like '%Red%Hat%Enterprise%Linux%' or name  like '%BSD%' or name  like '%Ubuntu%Linux%' OR name  like '%CentOS%Update%' or name  like '%Fedora%Linux%' or name  like '%Debian%Linux%' or name  like 'Mandriva Linux%' then 'Linux OS'
when name  like 'IBM AIX I%' or name  like 'IBM AIX' then 'AIX OS'
when name  like '%HP-UX%' then 'HP-UX'
when name  like 'Oracle Solaris%Update%' then 'Solaris OS'
else 'Non-OS'
end as nvarchar(64)) Patch_Type,
CAST(
case
when name  like ('%chrome%') then 'Chrome' 
when name  like ('%shockwave%') then 'Shockwave' 
when name  like ('%adobe%flash%') then 'Flash' 
when name  like ('%adobe%reader%') or name  like ('%adobe%acrobat%') then 'Acrobat' 
when name  like ('%adobe%illustrator%') then 'Illustrator' 
when name  like ('%adobe%photoshop%') then 'Photoshop' 
when name  like ('%apple%iOS%') then 'iOS' 
when name  like ('%quicktime%') then 'QuickTime' 
when name  like ('%safari%') then 'Safari' 
when name  like ('%iTunes%') then 'iTunes' 
when name  like ('% IIS %') or name  like ('IIS %') then 'IIS' 
when name  like ('%Internet Explorer%') or name  like ('%Microsoft IE%') then 'IE' 
when name  like ('%Microsoft Office%') or name  like ('%Office 20%') or name  like ('%Microsoft%Excel%')  or name  like ('%Microsoft%Word%')
or name  like ('%Microsoft%Powerpoint%') or name  like ('%Microsoft%Project%') or name  like ('%Microsoft%OneNote%') 
or name  like ('%Microsoft%Publisher%') or name  like ('%Microsoft%Visio%')  then 'Office' 
when name  like ('%Outlook%') then 'Outlook' 
when name  like ('%SQL Server%') then 'SQL Server' 
when name  like ('%Windows%Media') then 'Windows Media Player' 
when name  like '(MS%' OR name  like 'Microsoft%' OR name  like '%DirectAccess%' OR name  like '%Microsoft Windows%' then 'Windows' 
when name  like ('%DirectX%') then 'DirectX' 
when name  like ('%.NET%') then '.NET' 
when name  like ('%AnyConnect%') then 'AnyConnect' 
when name  like ('%Webex%') then 'Webex' 
when name  like ('%Firefox%') then 'Firefox' 
when name  like ('%IBM DB2%') then 'DB2' 
when name  like ('%IBM%Lotus%') or name  like ('%IBM%Notes%') or name  like ('%IBM%Domino%') then 'Lotus Notes/Domino' 
when name  like ('%java%') then 'Java' 
when name  like ('%IBM%WebSphere') then 'WebSphere' 
when name  like ('%Visual Studio%') then 'Visual Studio' 
when name  like ('%Thunderbird%') then 'Thunderbird' 
when name  like ('%SeaMonkey%') then 'SeaMonkey' 
when name  like ('%MySQL%') then 'MySQL' 
when name  like ('%OpenSSL%') then 'OpenSSL' 
when name  like ('%Opera%') then 'Opera Browser' 
when name  like ('%Oracle Database%') then 'Database' 
when name  like ('%RealPlayer%') then 'RealPlayer' 
when name  like ('%VideoLan VLC%') or name  like ('%VLC Media%') then 'VLC Media Player' 
when name  like ('%VMWare Workstation%') then 'VMWare Workstation' 
when name  like ('%Wireshark%') then 'Wireshark' 
when name  like ('%Yahoo%Messenger%') then 'Messenger' 
when name  like ('%policy%') then 'Policy' 
when name  like ('%System%Management%Homepage') then 'HP System Management Homepage' 
when name  like ('%XML%Core%Services%') then 'XML Core Services' 
when name  like ('%pcAnywhere%') then 'PcAnywhere' 
when name  like ('%IBM%AIX%I%') then 'IBM' 
when name  like ('Samba%') then 'Samba' 
when name  like ('Sendmail%') then 'Sendmail'
when name  like ('%Red Hat Enterprise%') then 'Red Hat'
when name  like ('%SUSE%Linux%') then 'SUSE' 
when name  like ('%BSD%') then 'FreeBSD' 
when name  like ('%Ubuntu%Linux%') then 'Ubuntu'
when name  like ('%CentOS%Update%') then 'CentOS' 
when name  like ('%Fedora%Linux%')  then 'Fedora'
when name  like ('%Debian%Linux%') then 'Debian' 
when name  like ('Mandriva Linux%') then 'Mandriva'
when name  like '%HP-UX%' then 'HP-UX'
when name  like ('%Slackware%Linux%') then 'Slackware'
when name  like ('%ClamAv%') then 'ClamAV'
when name  like ('%GNU Bash%') then 'GNU Bash'
when name  like ('%Openoffice%') then 'OpenOffice'
when name  like ('%WU-FTPD%') then 'WU-FTPD'
else 'Other'
end as nvarchar(64)) Product,
CASE
WHEN vln.FaultlineID IN ('8013','12640','15131','15142','15156','15189','15207','15287','6457','7132','8300','8440','10000','10945','12007','12206','12703','13461','13465','14082') THEN 'Patch'
WHEN vln.FaultlineID = '10615' then 'Configure'
ELSE CAT.solution_category
END Solution_Category,
Patched,
HIP,
VSE,
CASE
WHEN TP_DC.FaultlineID IS not null then 1
else 0
END TP_DC,
CASE
WHEN TP_INT.FaultlineID IS not null then 1
else 0
END TP_INT,
basescorevalue, 
BaseExploitabilityValue, 
BaseImpactValue,
Exploitability_Rating,
Exploit_Potential,
MVM_Exploitability,
/* Assign a value of 0 if the value is Null */
CASE 
WHEN BaseExploitabilityValue IS NULL THEN 0 
ELSE BaseExploitabilityValue 
END BaseExploitabilityValue_PRI, 
/* Assign a value of 0 if the value is Null */
CASE 
WHEN BaseScoreValue IS NULL THEN 0 
ELSE BaseScoreValue 
END BaseScoreValue_PRI, 
/* Assign a value of 0 if the value is Null */
CASE 
WHEN BaseImpactValue IS NULL THEN 0 
ELSE BaseImpactValue 
END BaseImpactValue_PRI,
CASE 
WHEN (mra.fid IS NOT NULL AND mra.VSE = 1 AND mra.HIP = 1) THEN 1
WHEN (mra.fid IS NOT NULL AND mra.HIP = 1 AND mra.VSE = 0) THEN 3  
WHEN ((mra.fid IS NOT NULL AND mra.HIP = 0 AND mra.VSE = 1) OR TP_DC.FaultlineID IS NOT NULL) THEN 5 
ELSE 10 
END Mitigation_Value_Server,
CASE 
WHEN (mra.fid IS NOT NULL AND mra.VSE = 1 AND mra.HIP = 1) THEN 1
WHEN (mra.fid IS NOT NULL AND mra.HIP = 1 AND mra.VSE = 0) THEN 3  
WHEN ((mra.fid IS NOT NULL AND mra.HIP = 0 AND mra.VSE = 1) OR TP_INT.FaultlineID IS NOT NULL) THEN 5 
ELSE 10 
END Mitigation_Value_WKS,
ROW_NUMBER() OVER (PARTITION BY vln.faultlineid ORDER BY (CASE exploitability_rating WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 END) ASC ) AS RANK
FROM faultline.Content.vuln vln

/* Derive MRA Mitigations */
LEFT JOIN
(
SELECT FID,
Case WHEN HIP >= 1 THEN 1 ELSE 0
End HIP,
CASE WHEN VSE >= 1 THEN 1 ELSE 0 End VSE
FROM (
SELECT DISTINCT [AttributeValue] FID, 
SUM(CASE WHEN HIP = 1 then 1 else 0 END) HIP, 
SUM(CASE WHEN VSE = 1 then 1 else 0 END) VSE
FROM [VRAT].[dbo].[MRA_Mit] with (nolock)
GROUP BY [AttributeValue]
) T1
) MRA ON MRA.FID = vln.faultlineID

/* Derive the Solution Category */
LEFT JOIN (SELECT FaultlineID, SC_Derived Solution_Category FROM vrat.dbo.vwFID_SC_Derived) CAT ON CAT.FaultlineID = vln.faultlineID 

/* Join vulnerability score details where the scoretype is 3 */
LEFT JOIN
(
SELECT faultlineid, 
basescorevalue, 
ScoreType, 
BaseExploitabilityValue, 
BaseImpactValue
FROM faultline.dbo.cvsscore
WHERE scoretype = 3
) CVS ON CVS.FaultlineID = vln.faultlineID

LEFT JOIN VRAT.dbo.vwTP_Mit_FID_DC TP_DC on TP_DC.FaultlineID = vln.faultlineid

LEFT JOIN VRAT.dbo.vwTP_Mit_FID_Int TP_INT on TP_INT.FaultlineID = vln.faultlineid

LEFT JOIN [VRAT].[dbo].[vwExploitability] exploit on exploit.faultlineid = vln.faultlineid
) T1
WHERE RANK = 1
) T2
) T3
