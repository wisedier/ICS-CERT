import React, { Component } from 'react';
import { ResponsiveBar } from '@nivo/bar';
import { ResponsivePie } from '@nivo/pie'

import './App.css';
import vulnerabilities from './vulnerabilities.json';

const has = Object.prototype.hasOwnProperty;


class App extends Component {

  getNivoBarData() {
    const colors = {
      'very low': '#6c757d',
      'low': '#007bff',
      'medium': '#17a2b8',
      'high': '#ffc107',
      'very high': '#dc3545',
    };
    const nivoData = {
      data: [],
      keys: [],
      indexBy: 'cwe',
      margin: {
        top: 40,
        right: 10,
        bottom: 40,
        left: 140,
      },
      padding: 0.3,
      borderColor: 'inherit:darker(1.6)',
      axisTop: {
        tickSize: 5,
        tickPadding: 5,
        tickRotation: 0,
        legendPosition: 'middle',
        legendOffset: 32,
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
      labelTextColor: 'inherit:darker(1.6)',
      animate: true,
      motionStiffness: 90,
      motionDamping: 15,
      legends: [
        {
          dataFrom: 'keys',
          anchor: 'top-left',
          direction: 'column',
          justify: false,
          translateX: -140,
          translateY: 0,
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
      layout: 'horizontal',
      colors: Object.values(colors),
    };
    const cweRange = {};
    const barData = Object.values(vulnerabilities).reduce((result, l) => result.concat(l));

    for (const data of barData) {
      const cwe = data.cwe.replace(' ', '');
      const vulnerability = data.vulnerability ? data.vulnerability.toUpperCase() : null;

      if (!has.call(cweRange, cwe)) {
        cweRange[cwe] = {
          vulnerability,
          'very low': 0,
          'low': 0,
          'medium': 0,
          'high': 0,
          'very high': 0,
        };
      }

      let key = '';
      if (data.cvss < 2.0) {
        key = 'very low';
      } else if (data.cvss < 4.0) {
        key = 'low';
      } else if (data.cvss < 6.0) {
        key = 'medium';
      } else if (data.cvss < 8.0) {
        key = 'high';
      } else {
        key = 'very high';
      }

      cweRange[cwe][key] += 1;
    }

    const cweKeys = ['very low', 'low', 'medium', 'high', 'very high'];
    nivoData.keys = [...cweKeys];
    for (const cwe in cweRange) {
      if (!has.call(cweRange, cwe)) {
        continue;
      }

      const data = { cwe };
      let totalCount = 0;
      for (const key of nivoData.keys) {
        const count = cweRange[cwe][key];
        totalCount += count;
        data[key] = count;
        data[`${key}Color`] = colors[key];
      }
      data.vulnerability = cweRange[cwe].vulnerability;
      data['totalCount'] = totalCount;
      nivoData.data.push(data);
    }
    nivoData.data.sort((d1, d2) => {
      let d1Count = cweKeys.map(key => d1[key]).reduce((sum, x) => sum + x);
      let d2Count = cweKeys.map(key => d2[key]).reduce((sum, x) => sum + x);
      return d1Count - d2Count;
    });
    return nivoData;
  }

  getNivoPieData() {
    const data = [];
    const nivoData = {
      margin: {
        'top': 40,
        'right': 80,
        'bottom': 80,
        'left': 80,
      },
      innerRadius: 0.5,
      padAngle: 0.7,
      cornerRadius: 3,
      colors: 'nivo',
      colorBy: 'id',
      borderWidth: 1,
      borderColor: 'inherit:darker(0.2)',
      radialLabelsSkipAngle: 1,
      radialLabelsTextXOffset: 6,
      radialLabelsTextColor: '#333333',
      radialLabelsLinkOffset: 0,
      radialLabelsLinkDiagonalLength: 16,
      radialLabelsLinkHorizontalLength: 24,
      radialLabelsLinkStrokeWidth: 1,
      radialLabelsLinkColor: 'inherit',
      slicesLabelsSkipAngle: 3,
      slicesLabelsTextColor: '#333333',
      animate: true,
      motionStiffness: 90,
      motionDamping: 15,
      legends: [],
    };

    for (const vendor in vulnerabilities) {
      if (!has.call(vulnerabilities, vendor)) {
        continue;
      }
      data.push({
        id: vendor,
        label: vendor,
        value: vulnerabilities[vendor].length,
      });
    }

    data.sort((d1, d2) => d2.value - d1.value);
    console.log(data.length);
    nivoData.data = data.slice(0, 90);
    nivoData.data.push({
      id: 'others',
      label: 'others',
      value: data.slice(90).map(item => item.value).reduce((sum, value) => sum + value),
    });
    return nivoData;
  }

  getCweTable(data) {
    const cwes = [...data];
    cwes.reverse();
    return cwes.map(item => <tr key={ item.cwe }>
      <td>{ item.cwe }</td>
      <td>{ item.vulnerability }</td>
    </tr>);
  }

  render() {
    const nivoBarData = this.getNivoBarData();
    const nivoPieData = this.getNivoPieData();
    return (
      <div>
        <div className="bar" style={ { display: 'none' } }>
          <div style={ { width: '100%' } }>
            <h3 style={ { textAlign: 'center' } }>ICS-CERT Advisories</h3>
          </div>
          <div style={ { width: '100%' } }>
            <div className="App" style={ { width: '55%', height: '5400px', float: 'left' } }>
              <ResponsiveBar { ...nivoBarData } />
            </div>
            <div style={ { width: '45%', float: 'right' } }>
              <table style={ { boxSizing: 'border-box', fontSize: '0.8em' } }>
                <thead>
                <tr>
                  <th>CWE</th>
                  <th>VULNERABILITY</th>
                </tr>
                </thead>
                <tbody>{ this.getCweTable(nivoBarData.data) }</tbody>
              </table>
            </div>
          </div>
        </div>
        <div className="pie">
          <div style={ { width: '100%' } }>
            <div className="App" style={ { width: '100%', height: '1240px' } }>
              <ResponsivePie { ...nivoPieData } />
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default App;
