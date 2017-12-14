package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/lib/pq"
)

// Defaults for database connection
const (
	DefaultDbName     = "rhnschema"
	DefaultDbUser     = "rhnuser"
	DefaultDbPassword = "rhnpw"
	DefaultDbHost     = "localhost"
	DefaultDbPort     = 5432
)

var db *sql.DB

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func splitFilename(pkg string) (string, string, string, string, string) {
	if string(pkg[len(pkg)-4:]) == ".rpm" {
		pkg = pkg[0 : len(pkg)-4]
	}

	archIndex := strings.LastIndex(pkg, ".")
	arch := pkg[archIndex+1:]

	relIndex := strings.LastIndex(pkg[:archIndex], "-")
	rel := pkg[relIndex+1 : archIndex]

	verIndex := strings.LastIndex(pkg[:relIndex], "-")
	ver := pkg[verIndex+1 : relIndex]

	epochIndex := strings.Index(pkg, ":")
	var epoch string
	if epochIndex == -1 {
		epoch = ""
	} else {
		epoch = pkg[:epochIndex]
	}

	name := pkg[epochIndex+1 : verIndex]

	return name, ver, rel, epoch, arch
}

func getChannels(n, v, r, e, a string) []int {
	var epochExpr string
	if e == "" {
		epochExpr = "epoch is null or"
	}
	theSQL := fmt.Sprintf(`
        select channel_id
        from rhnchannelpackage
        where package_id = (select id from rhnpackage where name_id = (select id from rhnpackagename where name = $1)
        and evr_id = (select id from rhnpackageevr where (%s epoch = $2)
        and version = $3 and release = $4)
        and package_arch_id = LOOKUP_PACKAGE_ARCH($5))
        `, epochExpr)
	rows, err := db.Query(theSQL, n, e, v, r, a)
	checkErr(err)
	defer rows.Close()
	var channels []int
	for rows.Next() {
		var channelID int
		err = rows.Scan(&channelID)
		checkErr(err)
		channels = append(channels, channelID)
	}
	return channels
}

func getChannelFamilies(channels []int) []int {
	theSQL := `
        select f.id
        from rhnchannelfamily f
        join rhnchannelfamilymembers fm on f.id = fm.channel_family_id
        where fm.channel_id = any($1)
        `
	rows, err := db.Query(theSQL, pq.Array(channels))
	checkErr(err)
	defer rows.Close()
	var families []int
	for rows.Next() {
		var channelFamilyID int
		err = rows.Scan(&channelFamilyID)
		checkErr(err)
		families = append(families, channelFamilyID)
	}
	return families
}

func getResult(n, v, r, e, a string, families []int) []int {
	var epochExpr string
	if e == "" {
		epochExpr = "epoch is null or"
	}
	theSQL := fmt.Sprintf(`
        select package_id
        from rhnchannelpackage join rhnchannel on rhnchannelpackage.channel_id = rhnchannel.id
        join rhnchannelfamilymembers on rhnchannelfamilymembers.channel_id = rhnchannel.id
        join rhnchannelfamily on rhnchannelfamily.id = rhnchannelfamilymembers.channel_family_id and rhnchannelfamily.id = any($1)
        where package_id in (select rhnpackage.id from rhnpackage join rhnpackageevr on rhnpackage.evr_id = rhnpackageevr.id where name_id in (select id from rhnpackagename where name = $2)
        and package_arch_id = LOOKUP_PACKAGE_ARCH($3)
        and rhnpackageevr.evr > (select evr from rhnpackageevr where ((%s epoch = $4)) and version = $5 and release = $6))
        `, epochExpr)
	rows, err := db.Query(theSQL, pq.Array(families), n, a, e, v, r)
	checkErr(err)
	defer rows.Close()
	var packages []int
	for rows.Next() {
		var packageID int
		err = rows.Scan(&packageID)
		checkErr(err)
		packages = append(packages, packageID)
	}
	return packages
}

func getAll(packages []int) []map[string]interface{} {
	theSQL := `select e.advisory_name, ep.package_id, evr.evr, c.label from rhnerrata e join rhnerratapackage ep on e.id = ep.errata_id left join rhnpackage p on ep.package_id = p.id join rhnpackageevr evr on p.evr_id = evr.id left join rhnchannelpackage cp on cp.package_id = p.id join rhnchannel c on c.id = cp.channel_id where advisory_type = 'Security Advisory' and ep.package_id = any($1)`
	rows, err := db.Query(theSQL, pq.Array(packages))
	checkErr(err)
	defer rows.Close()
	var updates []map[string]interface{}
	for rows.Next() {
		var advisoryName, evr, channel string
		var packageID int
		err = rows.Scan(&advisoryName, &packageID, &evr, &channel)
		checkErr(err)
		item := make(map[string]interface{})
		item["advisory_name"] = advisoryName
		item["package_id"] = packageID
		item["evr"] = evr
		item["label"] = channel
		updates = append(updates, item)
	}
	return updates
}

func process(pkg string) []map[string]interface{} {
	n, v, r, e, a := splitFilename(pkg)
	channels := getChannels(n, v, r, e, a)
	families := getChannelFamilies(channels)
	packages := getResult(n, v, r, e, a, families)
	res := getAll(packages)
	return res
}

func apiErrata(w http.ResponseWriter, r *http.Request) {
	pkg := r.URL.Query().Get("pkg")
	fmt.Printf("Endpoint hit: errata - '%s'\n", pkg)
	if pkg == "" {
		fmt.Fprintln(w, "Invalid pkg parameter.")
	} else {
		res := process(pkg)
		output, err := json.Marshal(res)
		checkErr(err)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(output))
	}
}

func handleRequests() {
	http.HandleFunc("/errata", apiErrata)
	http.ListenAndServe(":8080", nil)
}

func printHelp() {
	flag.PrintDefaults()
	fmt.Println("\nThis runs in three modes.")
	fmt.Println("Example:")
	fmt.Println("./errata --pkg firefox-52.3.0-2.el7_4.i686 # stdout output")
	fmt.Println("./errata --pkgfile ~/file-with-list-of-nevra-per-line # stdout output")
	fmt.Println("./errata --api # API on port 8080")
}

func processPackageName(pkg *string) {
	res := process(*pkg)
	for _, item := range res {
		fmt.Println(item)
	}
}

func main() {
	// Setup arguments
	dbName := flag.String("dbname", DefaultDbName, "database name to connect to")
	dbUser := flag.String("username", DefaultDbUser, "database user name")
	dbPassword := flag.String("password", DefaultDbPassword, "password to use")
	dbHost := flag.String("host", DefaultDbHost, "database server host")
	dbPort := flag.Int("port", DefaultDbPort, "database server port")
	help := flag.Bool("help", false, "print help")
	flag.BoolVar(help, "h", false, "print help")
	api := flag.Bool("api", false, "run in API mode")
	pkg := flag.String("pkg", "", "package to query")
	pkgFile := flag.String("pkgfile", "", "read package names from file")
	flag.Parse()

	// Print help
	if *help || (!*api && *pkg == "" && *pkgFile == "") {
		printHelp()
		os.Exit(0)
	}

	// Connect to DB
	dbinfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", *dbHost, *dbPort,
		*dbUser, *dbPassword, *dbName)
	var err error
	db, err = sql.Open("postgres", dbinfo)
	checkErr(err)
	defer db.Close()

	// Run as API server or print directly results for single package
	if *api {
		fmt.Println("Running API on port 8080")
		handleRequests()
	} else if *pkgFile != "" {
		file, err := os.Open(*pkgFile)
		checkErr(err)
		var packagesToProcess []string
		fscanner := bufio.NewScanner(file)
		for fscanner.Scan() {
			line := fscanner.Text()
			if line != "" {
				packagesToProcess = append(packagesToProcess, line)
			}
		}

		for _, pkg := range packagesToProcess {
			processPackageName(&pkg)
		}
	} else {
		processPackageName(pkg)
	}
}
