package models

import (
	"encoding/json"
	"fmt"
    "log"
    "time"
    "strconv"
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

type Paras struct {
    Name string
    Time int
}

type WafContent struct {
    Time        int64  `json:"time"`
    Client      string `json:"client"`
    HostName    string `json:"hostName"`
    Rev         string `json:"rev"`
    Message     string `json:"msg"`
    Attack      string `json:"attack"`
    Severity    int    `json:"severity"`
    Maturity    int    `json:"maturity"`
    Accuracy    int    `json:"accuracy"`
    Uri         string `json:"uri"`
    UniqueId    string `json:"unique_id"`
    Ref         string `json:"ref"`
    Tags        string `json:"tags"`
    RuleFile    string `json:"ruleFile"`
    RuleLine    int    `json:"ruleLine"`
    RuleId      int    `json:"ruleId"`
    RuleData    string `json:"ruleData"`
    RuleVersion string `json:"ruleVersion"`
    Version     string `json:"version"`
}
type VdsContent struct {
    ThreatName      string `json:"threatName"`
    SubFile         string `json:"subFile"`
    LocalThreatName string `json:"localThreatName"`
    LocalVType      string `json:"localVType"`
    LocalPlatfrom   string `json:"localPlatfrom"`
    LocalVName      string `json:"localVName"`
    LocalExtent     string `json:"localExtent"`
    LocalEngineType string `json:"localEngineType"`
    LocalLogType    string `json:"localLogType"`
    LocalEngineIP   string `json:"localEngineIP"`
    LogTime         int64  `json:"time"`

    SrcIp    string `json:"srcIp"`
    SrcPort  int    `json:"srcPort"`
    DestIp   string `json:"destIp"`
    DestPort int    `json:"destPort"`
    AppFile  string `json:"filePath"`
    HttpUrl  string `json:"url"`
}

type WafData struct {
    Num int `json:"num"`
    Data []WafContent `json:"data"`
}
type VdsData struct {
    Num int `json:"num"`
    Data []VdsContent `json:"data"`
}

var WafRes []WafData
var VdsRes []VdsData

var EngineType string
var StartTime, StopTime int64

var DbHdl *sql.DB

func Dereplication(para string) string {
    Db("root", "mysqladmin", "10.88.1.102", "aptwebservice")

	var p Paras
	json.Unmarshal([]byte(para), &p)
    TaskInfo(p.Name, p.Time)
    res := Res()
	return res
}

func Db (usr, pwd, host, db string) {
    var err error

    connParams := usr + ":" + pwd + "@tcp(" + host + ":3306)/" + db
    DbHdl, err = sql.Open("mysql", connParams)    
    if err != nil {
        log.Fatal(err)
    }

    err = DbHdl.Ping()
    if err != nil {
        log.Fatal(err)
    }
}

func TaskInfo(paraName string, paraTime int) {
	var startStr string
	var endStr string

	query := fmt.Sprintf(`select type, start, end from %s where name='%s' and time=%d;`,
		                 "offline_assignment", paraName, paraTime)
	err := DbHdl.QueryRow(string(query)).Scan(&EngineType, &startStr, &endStr)
	if err != nil {
        log.Fatal(err)
	}


    startDate := startStr[:10]
    startU, _ := time.Parse("2006/01/02", startDate)
    startHour := startStr[11:]
    s, err := strconv.Atoi(startHour)
    s = s * 60 * 60
    StartTime = startU.Unix() + int64(s)
 
    endDate := endStr[:10] 
    endHour := endStr[11:]
    endU, _ := time.Parse("2006/01/02", endDate)    
    s, err = strconv.Atoi(endHour)
    s = s * 60 * 60
    StopTime = endU.Unix() + int64(s)
}

func PrepareSql(aimTbl string, referTbl string) string {
    var resFields []string
    if EngineType == "vds" {
        resFields = []string{"log_time", "threatname", "subfile", "local_threatname", 
                             "local_vtype", "local_platfrom", "local_vname", "local_extent", 
                             "local_enginetype", "local_logtype", "local_engineip",
                             "sourceip", "destip", "sourceport", "destport", "app_file", "http_url"}
    } else {
        resFields = []string{"time", "client", "rev", "msg", "attack", "severity", "maturity", 
                             "accuracy", "hostname", "uri", "unique_id", "ref", "tags", "rule_file", 
                             "rule_line", "rule_id", "rule_data", "rule_ver", "version"}
    }

    resFieldsStr := ""
    len := len(resFields)
    for key, field := range resFields {
        if key < len -1 {
            resFieldsStr = resFieldsStr + field + ", " 
        } else {
            resFieldsStr = resFieldsStr + field 
        }
    }

    equalFieldsStr := "" 
    for key, field := range resFields {
        if key < len - 1 {
            equalFieldsStr = equalFieldsStr + aimTbl+ "." + field + " = " + referTbl+ "." + field + " and "
        } else {
            equalFieldsStr = equalFieldsStr + aimTbl+ "." + field + " = " + referTbl+ "." + field
        }
    }

    sql := "select " + resFieldsStr + " from " + aimTbl+ " where not exists (" +
            "select * from " + referTbl+ " where " + equalFieldsStr + " and " +
            aimTbl+ ".log_time >= " + strconv.FormatInt(StartTime, 10) + 
            " and " + aimTbl+ ".log_time <= " + strconv.FormatInt(StopTime, 10) + ")" + 
            " and " + aimTbl+ ".log_time >= " + strconv.FormatInt(StartTime, 10) + 
            " and " + aimTbl+ ".log_time <= " + strconv.FormatInt(StopTime, 10) 
    
    fmt.Println(sql)
    return sql
}

func WafEngine(sql string) []WafContent {
    rows, err := DbHdl.Query(sql)
    if err != nil {
        log.Fatal(err)
    }

    defer rows.Close()

    var resSlice []WafContent
    var res WafContent 
    for rows.Next() {
        err := rows.Scan(&res.Time, &res.Client, &res.Rev, &res.Message, &res.Attack, &res.Severity,
                         &res.Maturity, &res.Accuracy, &res.HostName, &res.Uri, &res.UniqueId,
                         &res.Ref, &res.Tags, &res.RuleFile, &res.RuleLine, &res.RuleId, &res.RuleData,
                         &res.RuleVersion, &res.Version)
        if err != nil {
            log.Fatal(err)
        }
        resSlice = append(resSlice, res)
    }

    err = rows.Err()
    if err != nil {
        log.Fatal(err)
    }

    return resSlice 
}

func VdsEngine(sql string) []VdsContent {
    rows, err := DbHdl.Query(sql)
    if err != nil {
        log.Fatal(err)
    }

    defer rows.Close()

    var resSlice []VdsContent
    var res VdsContent 

    for rows.Next() {
        err := rows.Scan(&res.LogTime, &res.ThreatName, &res.SubFile, &res.LocalThreatName, &res.LocalVType,
                         &res.LocalPlatfrom, &res.LocalVName, &res.LocalExtent, &res.LocalEngineType,
                         &res.LocalLogType, &res.LocalEngineIP, &res.SrcIp, &res.DestIp, &res.SrcPort, 
                         &res.DestPort, &res.AppFile, &res.HttpUrl)
        if err != nil {
            log.Fatal(err)
        }
        resSlice = append(resSlice, res)
    }

    err = rows.Err()
    if err != nil {
        log.Fatal(err)
    }
	return resSlice
}

func Res() string {
    if EngineType == "waf" {
        sql := PrepareSql("alert_waf", "alert_waf_offline")
        onlineRes := WafEngine(sql)
        onlineLen := len(onlineRes)
        waf := WafData{
            Num: onlineLen,
            Data: onlineRes,
        }
        WafRes = append(WafRes, waf)

        sql = PrepareSql("alert_waf_offline", "alert_waf")
        offlineRes := WafEngine(sql)
        offlineLen := len(offlineRes)
        waf = WafData{
            Num: offlineLen,
            Data: offlineRes,
        }
        WafRes = append(WafRes, waf)
    } else {
        sql := PrepareSql("alert_vds", "alert_vds_offline")
        onlineRes := VdsEngine(sql)
        onlineLen := len(onlineRes)
        vds := VdsData{
            Num: onlineLen,
            Data: onlineRes,
        }
        VdsRes = append(VdsRes, vds)

        sql = PrepareSql("alert_vds_offline", "alert_vds")
        offlineRes := VdsEngine(sql)
        offlineLen := len(offlineRes)
        vds = VdsData{
            Num: offlineLen,
            Data: offlineRes,
        }
        VdsRes = append(VdsRes, vds)
    }

    var bytes []byte

    if len(VdsRes) != 0 {
        bytes, _ = json.Marshal(VdsRes)
    } else {
        bytes, _ = json.Marshal(WafRes)
    }
    
    return string(bytes)
}
