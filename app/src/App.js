import React from 'react';
import { ResponsiveBar } from "@nivo/bar";

import './App.css';
import vulnerabilities from './vulnerabilities.json';
import { ResponsivePie } from '@nivo/pie';

const severityColorMap = {
  'very low': '#6c757d',
  'low': '#007bff',
  'medium': '#17a2b8',
  'high': '#ffc107',
  'very high': '#dc3545',
};

const getCWEBarAttributes = (data) => {
  const attrs = {
    data: [],
    keys: [],
    indexBy: 'cwe',
    margin: { top: 50, right: 10, bottom: 40, left: 60 },
    padding: 0.3,
    colors: { scheme: 'yellow_orange_red' },
    orderColor: { from: 'color', modifiers: [['darker', 1.6]] },
    axisRight: null,
    axisTop: {
      tickSize: 5,
      tickPadding: 5,
      tickRotation: 0,
      legend: '',
      legendOffset: 36
    },
    axisBottom: {
      tickSize: 5,
      tickPadding: 5,
      tickRotation: 0,
      legendPosition: 'middle',
      legendOffset: 32,
    },
    axisLeft: {
      tickSize: 5,
      tickPadding: 5,
      tickRotation: 0,
      legend: 'count',
      legendPosition: 'middle',
      legendOffset: -40,
    },
    labelSkipWidth: 12,
    labelSkipHeight: 12,
    labelTextColor: { from: 'color', modifiers: [['darker', 1.6]] },
    legends: [
      {
        dataFrom: 'keys',
        anchor: 'top-left',
        direction: 'row',
        justify: false,
        translateX: 0,
        translateY: -50,
        itemsSpacing: 2,
        itemWidth: 100,
        itemHeight: 20,
        itemDirection: 'left-to-right',
        itemOpacity: 0.85,
        symbolSize: 20,
        effects: [
          {
            on: 'hover',
            style: {
              itemOpacity: 1,
            },
          },
        ],
      },
    ],
    animate: true,
    motionStiffness: 90,
    motionDamping: 15,
    layout: 'horizontal',
    colros: Object.values(severityColorMap),
  }

  const cweData = {};
  const advisories = Object.values(data).reduce((result, adv) => result.concat(adv), []);

  for (const adv of advisories) {
    const cwe = adv.cwe.replace(' ', '');
    const vulnerability = adv.vulnerability ? adv.vulnerability.toUpperCase() : null;

    if (!Object.prototype.hasOwnProperty.call(cweData, cwe)) {
      cweData[cwe] = { vulnerability };
      for (const key in severityColorMap) {
        cweData[cwe][key] = 0;
      }
    }

    let key = '';
    if (adv.cvss < 2.0) {
      key = 'very low';
    } else if (adv.cvss < 4.0) {
      key = 'low';
    } else if (adv.cvss < 6.0) {
      key = 'medium';
    } else if (adv.cvss < 8.0) {
      key = 'high';
    } else {
      key = 'very high';
    }

    cweData[cwe][key] += 1;
  }

  attrs.keys = Object.keys(severityColorMap);

  for (const cwe in cweData) {
    const column = { cwe };
    let totalCount = 0;
    for (const key of attrs.keys) {
      const count = cweData[cwe][key];
      totalCount += count;
      column[key] = count;
      column[`${key}Color`] = severityColorMap[key];
    }
    column.vulnerability = cweData[cwe].vulnerability;
    column.totalCount = totalCount;
    attrs.data.push(column);
  }
  attrs.data.sort((c1, c2) => c1.totalCount - c2.totalCount);
  return attrs;
}

const getCWEPieAttributes = (data) => {
  const attrs = {
    margin: { top: 40, right: 80, bottom: 80, left: 80 },
    innerRadius: 0.35,
    padAngle: 0.7,
    cornerRadius: 3,
    colors: { scheme: 'nivo' },
    borderWidth: 1,
    borderColor: { from: 'color', modifiers: [['darker', 0.2]] },
    enableRadialLabels: true,
    radialLabelsSkipAngle: 0,
    radialLabelsTextXOffset: 6,
    radialLabelsTextColor: "#333333",
    radialLabelsLinkOffset: 0,
    radialLabelsLinkDiagonalLength: 16,
    radialLabelsLinkHorizontalLength: 24,
    radialLabelsLinkStrokeWidth: 1,
    radialLabelsLinkColor: { from: 'color' },
    slicesLabelsSkipAngle: 2,
    slicesLabelsTextColor: "#333333",
    animate: true,
    motionStiffness: 90,
    motionDamping: 15,
    legends: [],
  };

  const cweData = [];

  for (const vendor in data) {
    if (!Object.prototype.hasOwnProperty.call(data, vendor)) {
      continue;
    }

    cweData.push({
      id: vendor,
      label: vendor,
      value: data[vendor].length,
    });

    cweData.sort((cwe1, cwe2) => cwe2.value - cwe1.value);
    const others = cweData.slice(90);
    attrs.data = cweData.slice(0, 90);
    attrs.data.push({
      id: `others - ${others.length} vendors`,
      label: `others - ${others.length} vendors`,
      value: others.map(item => item.value).reduce((sum, value) => sum + value, 0),
    });
  }
  return attrs;
}


const App = () => {
  const barAttrs = getCWEBarAttributes(vulnerabilities);
  const pieAttrs = getCWEPieAttributes(vulnerabilities);
  const advisories = [...barAttrs.data].reverse();

  return (
    <div>
      <div className="bar">
        <div style={{ width: '100%' }}>
          <h3 style={{ textAlign: 'center' }}>ICS-CERT Advisories</h3>
        </div>
        <div style={{ width: '100%' }}>
          <div className="App" style={{ width: '55%', height: '5400px', float: 'left' }}>
            <ResponsiveBar {...barAttrs} />
          </div>
          <div style={{ width: '45%', float: 'right' }}>
            <table style={{ boxSizing: 'border-box', fontSize: '0.8em' }}>
              <thead>
                <tr>
                  <th>CWE</th>
                  <th>VULNERABILITY</th>
                </tr>
              </thead>
              <tbody>
                {
                  advisories.map(adv => (
                    <tr key={adv.cwe}>
                      <td>{adv.cwe}</td>
                      <td>{adv.vulnerability}</td>
                    </tr>
                  ))
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <div className="pie">
        <div style={{ width: '100%' }}>
          <div className="App" style={{ width: '100%', height: '1240px' }}>
            <ResponsivePie {...pieAttrs}/>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
