# Police Salary Calculator

เว็บคำนวณเงินเดือน บำเหน็จ และบำนาญ พร้อมจัดเก็บตารางเงินเดือนส่วนกลางบน Neon PostgreSQL

## Environment

- `DATABASE_URL`: Neon PostgreSQL connection string (set only in Render environment variables)
- `PORT`: assigned automatically by Render

## Run locally

```bash
npm install
DATABASE_URL='postgresql://...' npm start
```

## API

- `GET /health`: application and database health
- `GET /api/salary-table`: read the shared salary table
- `PUT /api/salary-table`: save the shared salary table

Do not put database credentials in browser code or commit `.env` files.
