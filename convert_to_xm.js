#!/usr/bin/env node

const fs = require('fs')


fs.readFile(process.argv[2], 'utf8' , (err, data) => {
    if (err) {
      console.error(err)
      return
    }
    const scan = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))

    //console.log(scan.results.vulnerabilities[0].id)

    console.log(formatJUnitXML(scan.results))
})

function toSentenceCase(string) {
  return string[0].toUpperCase() + string.slice(1).toLowerCase();
}

function formatJUnitXML (results) {
  // Only 1 image can be scanned at a time
  const result = results[0]
  const vulnerabilities = result.vulnerabilities
  const compliances = result.compliances

  vuln_count = 0
  let vulns = []
  if (vulnerabilities) {
    vulns = vulnerabilities.map(vuln => {
      vuln_count = vuln_count + 1
      return '<testcase name="' + toSentenceCase(vuln.severity) + ' ' + vuln.id + ' found in ' + vuln.packageName 
                + vuln.packageVersion + '" classname="' + vuln.packageName + vuln.packageVersion + 
                '"><failure message="CVSS:' + vuln.cvss + '; ' + (vuln.status || 'not fixed') + ' | Published:' + 
                vuln.publishedDate + '&#xA;Description:' + vuln.description + '"/></testcase>'
    })
  }

  comp_count = 0
  let comps = []
  if (compliances) {
    comps = compliances.map(comp => {
      return '<testcase name="' + toSentenceCase(comp.severity) + ' severity compliance check ' + comp.title + 
                ' violated" classname="' + comp.id + '"><failure message="' + comp.description + '"/></testcase>'
    })
  }

  violations = vuln_count + comp_count
  head = '<?xml version="1.0" ?><testsuites><testsuite failures="' + violations + 
          '" name="violations" tests="' + violations + '" time="' + violations + '">'
  tail = '</testsuite></testsuites>'

  return [head, ...vulns, ...comps, tail].join("").toString()
}
