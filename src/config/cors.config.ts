const whitelist = process.env.CORS_URL as string

const corsOption = {
  origin: function (origin: string, callback: any) {
    if (whitelist.indexOf(origin) !== -1 || !origin) {
      callback(null, true)
    } else {
      callback(new Error('Not allowed by CORS'))
    }
  },
  credentials: true,
}

export default corsOption
