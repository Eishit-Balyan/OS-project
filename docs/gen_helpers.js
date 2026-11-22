/**
 * ============================================================================
 * Warden Documentation Builder
 * Target: docs/Warden_Help.docx
 * Format: A4, 2.5cm margins, Calibri 11pt, 1.15 line spacing, Consolas 10pt code,
 *         styled tables with repeating headers, TOC, real PAGE/NUMPAGES footer.
 * ============================================================================
 */

const docx = require('C:/Users/developer/.gemini/antigravity/brain/c26c76a5-c211-45f4-a0a9-fbb6fe66e4b1/scratch/node_modules/docx');
const fs = require('fs');
const path = require('path');

const {
  Document, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, PageNumber, NumberOfPages, TableOfContents,
  WidthType, BorderStyle, AlignmentType, HeadingLevel,
  ShadingType, LineRule
} = docx;

// Common styles & constants
const FONT_BODY = "Calibri";
const FONT_CODE = "Consolas";
const COLOR_BLACK = "000000";
const COLOR_MUTED = "444444";
const COLOR_BORDER = "B0B0B0";
const COLOR_SHADING = "D9D9D9";
const COLOR_CODE_BG = "F4F4F4";

const BORDER_SINGLE = { style: BorderStyle.SINGLE, size: 4, color: COLOR_BORDER };
const TABLE_BORDERS = {
  top: BORDER_SINGLE,
  bottom: BORDER_SINGLE,
  left: BORDER_SINGLE,
  right: BORDER_SINGLE,
  insideHorizontal: BORDER_SINGLE,
  insideVertical: BORDER_SINGLE
};

// Helper: standard body paragraph
function pBody(text, opts = {}) {
  return new Paragraph({
    alignment: AlignmentType.LEFT,
    spacing: { line: 276, lineRule: LineRule.AUTO, before: opts.before || 0, after: opts.after !== undefined ? opts.after : 120 },
    children: [
      new TextRun({
        text: text,
        font: FONT_BODY,
        size: 22, // 11pt
        color: COLOR_BLACK,
        bold: !!opts.bold,
        italics: !!opts.italics
      })
    ]
  });
}

// Helper: compound body paragraph
function pCompound(runs, opts = {}) {
  return new Paragraph({
    alignment: AlignmentType.LEFT,
    spacing: { line: 276, lineRule: LineRule.AUTO, before: opts.before || 0, after: opts.after !== undefined ? opts.after : 120 },
    children: runs.map(r => new TextRun({
      text: r.text,
      font: r.code ? FONT_CODE : FONT_BODY,
      size: r.code ? 20 : (r.size || 22),
      bold: !!r.bold,
      italics: !!r.italics,
      color: r.color || COLOR_BLACK
    }))
  });
}

// Helper: code block paragraph
function pCode(text, opts = {}) {
  return new Paragraph({
    alignment: AlignmentType.LEFT,
    spacing: { line: 240, lineRule: LineRule.AUTO, before: 40, after: opts.after !== undefined ? opts.after : 40 },
    shading: { fill: COLOR_CODE_BG, type: ShadingType.CLEAR },
    children: [
      new TextRun({
        text: text,
        font: FONT_CODE,
        size: 20, // 10pt
        color: COLOR_BLACK
      })
    ]
  });
}

// Helper: bullet paragraph
function pBullet(runs, opts = {}) {
  const bulletSymbol = "•  ";
  const allRuns = [
    new TextRun({ text: bulletSymbol, font: FONT_BODY, size: 22, bold: true, color: COLOR_BLACK }),
    ...runs.map(r => new TextRun({
      text: r.text,
      font: r.code ? FONT_CODE : FONT_BODY,
      size: r.code ? 20 : (r.size || 22),
      bold: !!r.bold,
      italics: !!r.italics,
      color: r.color || COLOR_BLACK
    }))
  ];
  return new Paragraph({
    indent: { left: 360, hanging: 240 },
    spacing: { line: 276, lineRule: LineRule.AUTO, before: 40, after: opts.after !== undefined ? opts.after : 80 },
    children: allRuns
  });
}

// Helper: Headings
function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 260, after: 120 },
    children: [
      new TextRun({
        text: text,
        font: FONT_BODY,
        size: 30, // 15pt
        bold: true,
        color: COLOR_BLACK
      })
    ]
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 200, after: 80 },
    children: [
      new TextRun({
        text: text,
        font: FONT_BODY,
        size: 26, // 13pt
        bold: true,
        color: COLOR_BLACK
      })
    ]
  });
}

function h3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 160, after: 60 },
    children: [
      new TextRun({
        text: text,
        font: FONT_BODY,
        size: 22, // 11pt
        bold: true,
        color: COLOR_BLACK
      })
    ]
  });
}

// Helper: Table creation
function createStyledTable(headers, rowsData, colWidthPercentages) {
  const tableRows = [];

  // Header row
  const headerCells = headers.map((hdr, idx) => {
    return new TableCell({
      width: { size: colWidthPercentages[idx], type: WidthType.PERCENTAGE },
      shading: { fill: COLOR_SHADING, type: ShadingType.CLEAR },
      margins: { top: 120, bottom: 120, left: 140, right: 140 },
      children: [
        new Paragraph({
          alignment: AlignmentType.LEFT,
          spacing: { line: 240, before: 0, after: 0 },
          children: [
            new TextRun({
              text: hdr,
              font: FONT_BODY,
              size: 20, // 10pt bold
              bold: true,
              color: COLOR_BLACK
            })
          ]
        })
      ]
    });
  });

  tableRows.push(new TableRow({
    tableHeader: true,
    cantSplit: true,
    children: headerCells
  }));

  // Data rows
  rowsData.forEach(row => {
    const cells = row.map((cellItem, idx) => {
      let paras = [];
      if (Array.isArray(cellItem)) {
        paras = cellItem;
      } else if (typeof cellItem === 'string') {
        paras = [
          new Paragraph({
            alignment: AlignmentType.LEFT,
            spacing: { line: 240, before: 0, after: 0 },
            children: [
              new TextRun({
                text: cellItem,
                font: FONT_BODY,
                size: 19, // 9.5pt
                color: COLOR_BLACK
              })
            ]
          })
        ];
      } else if (cellItem && cellItem.code) {
        paras = [
          new Paragraph({
            alignment: AlignmentType.LEFT,
            spacing: { line: 240, before: 0, after: 0 },
            children: [
              new TextRun({
                text: cellItem.text,
                font: FONT_CODE,
                size: 18,
                color: COLOR_BLACK
              })
            ]
          })
        ];
      } else if (cellItem && cellItem.runs) {
        paras = [
          new Paragraph({
            alignment: AlignmentType.LEFT,
            spacing: { line: 240, before: 0, after: 0 },
            children: cellItem.runs.map(r => new TextRun({
              text: r.text,
              font: r.code ? FONT_CODE : FONT_BODY,
              size: r.code ? 18 : 19,
              bold: !!r.bold,
              italics: !!r.italics,
              color: r.color || COLOR_BLACK
            }))
          })
        ];
      }

      return new TableCell({
        width: { size: colWidthPercentages[idx], type: WidthType.PERCENTAGE },
        margins: { top: 100, bottom: 100, left: 140, right: 140 },
        children: paras
      });
    });

    tableRows.push(new TableRow({
      cantSplit: true,
      children: cells
    }));
  });

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: TABLE_BORDERS,
    rows: tableRows
  });
}

console.log("Helper utilities initialized successfully.");
